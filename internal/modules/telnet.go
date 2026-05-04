package modules

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"entrypoint/internal/core"
)

type telnetModule struct{}

var shellPromptRE = regexp.MustCompile(`(?m)(^|\n)[^\r\n]{0,80}[#>$%] ?$`)
var telnetDialContext = defaultTelnetDialContext
var telnetReadUntilFunc = telnetReadUntil
var telnetProofSessionFunc = telnetProofSession
var telnetWriteLineFunc = telnetWriteLine

func NewTelnetModule() core.Module {
	return telnetModule{}
}

func (telnetModule) Name() string { return "telnet" }

func (telnetModule) Ports() []int { return []int{23} }

func (telnetModule) SupportsAnonymous() bool { return false }

func (telnetModule) SupportsCredentials() bool { return true }

func (telnetModule) Check(ctx context.Context, target core.Target, creds []core.Credential, opts core.Options) []core.Finding {
	if opts.AnonOnly {
		return []core.Finding{core.SkippedFinding(target, "anonymous", "anon-only mode; telnet has no anonymous auth")}
	}
	if len(creds) == 0 {
		return []core.Finding{core.SkippedFinding(target, "credential", "no credentials supplied for telnet")}
	}

	findings := make([]core.Finding, 0, len(creds))
	for _, cred := range creds {
		finding := checkTelnetAttempt(ctx, target, cred, opts.Timeout)
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

func checkTelnetAttempt(ctx context.Context, target core.Target, cred core.Credential, timeout time.Duration) core.Finding {
	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	conn, err := telnetDialContext(ctx, "tcp", address, timeout)
	if err != nil {
		return core.ErrorFinding(target, "credential", displayUser(cred), "", fmt.Sprintf("connect failed: %v", err))
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	banner, err := telnetReadUntilFunc(ctx, conn, timeout, func(s string) bool {
		return hasLoginPrompt(s) || hasPasswordPrompt(s) || hasAuthFailure(s) || hasShellPrompt(s)
	})
	if err != nil {
		return core.ErrorFinding(target, "credential", displayUser(cred), "", telnetStageError("login prompt", err))
	}
	banner = sanitizeTelnetText(banner)

	if hasAuthFailure(banner) {
		return core.InvalidFinding(target, "credential", displayUser(cred), banner, "login prompt already reports authentication failure")
	}
	if hasShellPrompt(banner) {
		return core.ErrorFinding(target, "credential", displayUser(cred), banner, "shell prompt appeared before credentials; refusing to guess state")
	}
	if !hasLoginPrompt(banner) && !hasPasswordPrompt(banner) {
		return core.ErrorFinding(target, "credential", displayUser(cred), banner, "no recognizable login or password prompt")
	}

	if hasLoginPrompt(banner) {
		if err := telnetWriteLineFunc(conn, cred.Username); err != nil {
			return core.ErrorFinding(target, "credential", displayUser(cred), banner, fmt.Sprintf("send username failed: %v", err))
		}

		passwordPrompt, readErr := telnetReadUntilFunc(ctx, conn, timeout, func(s string) bool {
			return hasPasswordPrompt(s) || hasAuthFailure(s) || hasLoginPrompt(s)
		})
		if readErr != nil {
			return core.ErrorFinding(target, "credential", displayUser(cred), banner, telnetStageError("password prompt", readErr))
		}
		if hasAuthFailure(passwordPrompt) {
			return core.InvalidFinding(target, "credential", displayUser(cred), banner, sanitizeTelnetText(passwordPrompt))
		}
		if !hasPasswordPrompt(passwordPrompt) {
			return core.ErrorFinding(target, "credential", displayUser(cred), banner, "username sent but password prompt not observed")
		}
	} else if hasPasswordPrompt(banner) && cred.Username != "" {
		// Some appliances present the password prompt immediately after a fixed username.
	}

	if err := telnetWriteLineFunc(conn, cred.Password); err != nil {
		return core.ErrorFinding(target, "credential", displayUser(cred), banner, fmt.Sprintf("send password failed: %v", err))
	}

	postAuth, err := telnetReadUntilFunc(ctx, conn, timeout, func(s string) bool {
		return hasAuthFailure(s) || hasShellPrompt(s) || hasLoginPrompt(s) || hasPasswordPrompt(s)
	})
	if err != nil {
		return core.ErrorFinding(target, "credential", displayUser(cred), banner, telnetStageError("authentication result", err))
	}
	postAuth = sanitizeTelnetText(postAuth)

	if hasAuthFailure(postAuth) || hasLoginPrompt(postAuth) || hasPasswordPrompt(postAuth) {
		return core.InvalidFinding(target, "credential", displayUser(cred), banner, postAuth)
	}

	if !hasShellPrompt(postAuth) {
		return core.ErrorFinding(target, "credential", displayUser(cred), banner, "credentials sent but no usable prompt observed")
	}

	proof, proofErr := telnetProofSessionFunc(ctx, conn, timeout)
	if proofErr == nil {
		return core.WithCredentialPassword(
			core.ValidFinding(target, "credential", displayUser(cred), proof, "telnet access confirmed via harmless command output"),
			cred.Password,
		)
	}

	// Prompt change alone is accepted only when it clearly looks like a real shell/device prompt.
	return core.WithCredentialPassword(
		core.ValidFinding(target, "credential", displayUser(cred), postAuth, "telnet access confirmed by post-auth prompt change; proof command unavailable"),
		cred.Password,
	)
}

func telnetProofSession(ctx context.Context, conn net.Conn, timeout time.Duration) (string, error) {
	commands := []string{"whoami", "id", "hostname", "show privilege"}
	for _, cmd := range commands {
		if err := telnetWriteLineFunc(conn, cmd); err != nil {
			return "", err
		}

		response, err := telnetReadUntil(ctx, conn, timeout, func(s string) bool {
			return hasShellPrompt(s) || hasAuthFailure(s)
		})
		if err != nil {
			continue
		}

		clean := sanitizeTelnetText(response)
		lower := strings.ToLower(clean)
		if hasAuthFailure(clean) {
			return "", errors.New("session returned to auth prompt during proof")
		}
		if strings.Contains(lower, strings.ToLower(cmd)) && shellPromptRE.MatchString(clean) {
			proof := formatTelnetProofEvidence(clean, cmd)
			if proof != "" {
				return fmt.Sprintf("%s => %s", cmd, proof), nil
			}
		}
	}

	return "", errors.New("no proof command produced recognizable output")
}

func telnetReadUntil(ctx context.Context, conn net.Conn, timeout time.Duration, matcher func(string) bool) (string, error) {
	var builder strings.Builder
	buffer := make([]byte, 1024)
	deadline := time.Now().Add(timeout)

	for {
		if err := ctx.Err(); err != nil {
			return builder.String(), err
		}
		if matcher(builder.String()) {
			return builder.String(), nil
		}
		if time.Now().After(deadline) {
			return builder.String(), context.DeadlineExceeded
		}

		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buffer)
		if n > 0 {
			visible, response := parseTelnetChunk(buffer[:n])
			builder.Write(visible)
			if len(response) > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
				_, _ = conn.Write(response)
			}
			if matcher(builder.String()) {
				return builder.String(), nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, io.EOF) && builder.Len() > 0 {
				if matcher(builder.String()) {
					return builder.String(), nil
				}
			}
			if err != nil {
				return builder.String(), err
			}
		}
	}
}

func telnetWriteLine(conn net.Conn, value string) error {
	_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := conn.Write([]byte(value + "\r\n"))
	return err
}

func parseTelnetChunk(data []byte) ([]byte, []byte) {
	visible := make([]byte, 0, len(data))
	response := make([]byte, 0)

	for i := 0; i < len(data); i++ {
		if data[i] != 255 {
			visible = append(visible, data[i])
			continue
		}

		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		if cmd == 255 {
			visible = append(visible, 255)
			i++
			continue
		}
		if cmd == 250 {
			for i+1 < len(data) {
				i++
				if data[i] == 255 && i+1 < len(data) && data[i+1] == 240 {
					i++
					break
				}
			}
			continue
		}
		if i+2 >= len(data) {
			break
		}
		opt := data[i+2]
		switch cmd {
		case 251, 252:
			response = append(response, 255, 254, opt) // DONT
		case 253, 254:
			response = append(response, 255, 252, opt) // WONT
		}
		i += 2
	}

	return visible, response
}

func hasLoginPrompt(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "login:") || strings.Contains(lower, "username:")
}

func hasPasswordPrompt(s string) bool {
	return strings.Contains(strings.ToLower(s), "password:")
}

func hasAuthFailure(s string) bool {
	lower := strings.ToLower(s)
	needles := []string{
		"login incorrect",
		"authentication failed",
		"access denied",
		"permission denied",
		"incorrect password",
	}
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func hasShellPrompt(s string) bool {
	return shellPromptRE.MatchString(sanitizeTelnetText(s))
}

func meaningfulLines(raw string, command string) []string {
	raw = sanitizeTelnetText(raw)
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.EqualFold(line, command) {
			continue
		}
		if shellPromptRE.MatchString(line) {
			continue
		}
		out = append(out, line)
	}
	return out
}

func formatTelnetProofEvidence(raw string, command string) string {
	lines := meaningfulLines(raw, command)
	if len(lines) == 0 {
		return ""
	}

	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if shouldDropTelnetProofLine(line) {
			continue
		}
		filtered = append(filtered, line)
	}
	if len(filtered) == 0 {
		filtered = lines
	}

	switch strings.ToLower(command) {
	case "whoami":
		return telnetWhoamiResult(filtered)
	case "hostname":
		return filtered[len(filtered)-1]
	case "id":
		for _, line := range filtered {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "uid=") || strings.Contains(lower, "gid=") {
				return line
			}
		}
		return filtered[len(filtered)-1]
	case "show privilege":
		for _, line := range filtered {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "privilege") || strings.Contains(lower, "current privilege level") {
				return line
			}
		}
		return filtered[len(filtered)-1]
	default:
		return filtered[len(filtered)-1]
	}
}

func shouldDropTelnetProofLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return true
	}

	prefixes := []string{
		"last login",
		"welcome to",
		"linux ",
		"kernel ",
		"system information",
		"system load",
		"memory usage",
		"swap usage",
		"processes:",
		"users logged in",
		"ip address for",
		"ipv4 address for",
		"ipv6 address for",
		"graph this data",
		"documentation:",
		"expanded security maintenance",
		"0 updates can be applied immediately",
		"new release",
		"*** system restart required ***",
		"activate the web console",
		"web console:",
		"register this system",
		"subscription status",
		"run '",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	contains := []string{
		"gnu/linux",
		"documentation:",
		"esm apps",
		"esm infra",
	}
	for _, needle := range contains {
		if strings.Contains(lower, needle) {
			return true
		}
	}

	return false
}

func telnetWhoamiResult(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 1 {
			return fields[0]
		}
	}
	return strings.TrimSpace(lines[len(lines)-1])
}

func sanitizeTelnetText(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.TrimSpace(s)
}

func defaultTelnetDialContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, network, address)
}

func telnetStageError(stage string, err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, io.EOF):
		return fmt.Sprintf("connection closed before %s", stage)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("timeout waiting for %s", stage)
	case errors.Is(err, net.ErrClosed):
		return fmt.Sprintf("connection closed before %s", stage)
	default:
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "use of closed network connection") || strings.Contains(lower, "closed network connection") {
			return fmt.Sprintf("connection closed before %s", stage)
		}
		return fmt.Sprintf("error waiting for %s: %v", stage, err)
	}
}
