package modules

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"entrypoint/internal/core"

	"golang.org/x/crypto/ssh"
)

type sshModule struct{}

var sshAttemptFunc = checkSSHAttempt

func NewSSHModule() core.Module {
	return sshModule{}
}

func (sshModule) Name() string { return "ssh" }

func (sshModule) Ports() []int { return []int{22} }

func (sshModule) SupportsAnonymous() bool { return false }

func (sshModule) SupportsCredentials() bool { return true }

func (sshModule) Check(ctx context.Context, target core.Target, creds []core.Credential, opts core.Options) []core.Finding {
	if opts.AnonOnly {
		return []core.Finding{core.SkippedFinding(target, "anonymous", "anon-only mode; ssh has no anonymous auth")}
	}
	if len(creds) == 0 {
		return []core.Finding{core.SkippedFinding(target, "credential", "no credentials supplied for ssh")}
	}

	findings := make([]core.Finding, 0, len(creds))
	for _, cred := range creds {
		finding := sshAttemptFunc(ctx, target, cred, opts.Timeout)
		findings = append(findings, finding)
		if finding.Success && opts.StopOnValid {
			break
		}
		if finding.Severity == core.SeverityError && ctx.Err() != nil {
			break
		}
	}
	return findings
}

func checkSSHAttempt(ctx context.Context, target core.Target, cred core.Credential, timeout time.Duration) core.Finding {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	conn, err := (&net.Dialer{}).DialContext(attemptCtx, "tcp", address)
	if err != nil {
		return core.ErrorFinding(target, "credential", displayUser(cred), "", fmt.Sprintf("connect failed: %v", err))
	}

	if deadline, ok := attemptCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := sshClient(conn, address, cred, timeout)
	if err != nil {
		_ = conn.Close()
		if isSSHAuthFailure(err) {
			return core.InvalidFinding(target, "credential", displayUser(cred), "", "login failed")
		}
		return core.ErrorFinding(target, "credential", displayUser(cred), "", fmt.Sprintf("ssh handshake failed: %v", sanitizeSSHError(err)))
	}
	defer client.Close()

	proof, err := sshProof(client)
	if err != nil {
		return core.ErrorFinding(target, "credential", displayUser(cred), "", fmt.Sprintf("ssh authentication succeeded but proof command failed: %v", sanitizeSSHError(err)))
	}

	return core.ValidFinding(target, "credential", displayUser(cred), proof, "ssh access confirmed")
}

func sshClient(conn net.Conn, address string, cred core.Credential, timeout time.Duration) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(cred.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
		BannerCallback: func(string) error {
			return nil
		},
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func sshProof(client *ssh.Client) (string, error) {
	commands := []string{"whoami", "id", "hostname"}
	var lastErr error

	for _, cmd := range commands {
		session, err := client.NewSession()
		if err != nil {
			lastErr = err
			continue
		}

		output, err := session.Output(cmd)
		_ = session.Close()
		if err != nil {
			lastErr = err
			continue
		}

		proof := formatSSHProofEvidence(string(output), cmd)
		if proof == "" {
			lastErr = errors.New("proof command returned no usable output")
			continue
		}
		return fmt.Sprintf("%s => %s", cmd, proof), nil
	}

	if lastErr == nil {
		lastErr = errors.New("no proof command succeeded")
	}
	return "", lastErr
}

func formatSSHProofEvidence(raw string, command string) string {
	lines := sshMeaningfulLines(raw)
	if len(lines) == 0 {
		return ""
	}

	switch strings.ToLower(command) {
	case "whoami":
		for i := len(lines) - 1; i >= 0; i-- {
			fields := strings.Fields(lines[i])
			if len(fields) == 1 {
				return fields[0]
			}
		}
		return lines[len(lines)-1]
	case "id":
		for _, line := range lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "uid=") || strings.Contains(lower, "gid=") {
				return line
			}
		}
		return lines[len(lines)-1]
	case "hostname":
		return lines[len(lines)-1]
	default:
		return lines[len(lines)-1]
	}
}

func sshMeaningfulLines(raw string) []string {
	raw = sanitizeTelnetText(raw)
	lines := strings.Split(raw, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || shouldDropTelnetProofLine(line) {
			continue
		}
		filtered = append(filtered, line)
	}
	return filtered
}

func isSSHAuthFailure(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	needles := []string{
		"unable to authenticate",
		"permission denied",
		"no supported methods remain",
		"cannot decode encrypted private keys",
	}
	for _, needle := range needles {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func sanitizeSSHError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, io.EOF):
		return "connection closed by remote host"
	case errors.Is(err, net.ErrClosed):
		return "connection closed by remote host"
	default:
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "use of closed network connection") || strings.Contains(lower, "closed network connection") {
			return "connection closed by remote host"
		}
		return strings.Join(strings.Fields(err.Error()), " ")
	}
}
