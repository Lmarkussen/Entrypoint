package modules

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"entrypoint/internal/core"
)

type redisModule struct{}

type redisResponse struct {
	kind byte
	text string
}

type redisClient interface {
	Close() error
	Do(args ...string) (redisResponse, error)
}

type redisWireClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

type redisAuthAttempt struct {
	username      string
	password      string
	passwordOnly  bool
	displayUser   string
	successPrefix string
}

var redisAttemptFunc = checkRedisAttempt
var redisDialFunc = newRedisClient

func NewRedisModule() core.Module {
	return redisModule{}
}

func (redisModule) Name() string { return "redis" }

func (redisModule) Ports() []int { return []int{6379} }

func (redisModule) SupportsAnonymous() bool { return true }

func (redisModule) SupportsCredentials() bool { return true }

func (redisModule) Check(ctx context.Context, target core.Target, creds []core.Credential, opts core.Options) []core.Finding {
	findings := make([]core.Finding, 0, len(creds)+1)

	if opts.IncludeAnon || opts.AnonOnly {
		finding := redisAttemptFunc(ctx, target, core.Credential{}, "anonymous", opts.Timeout)
		findings = append(findings, finding)
		if finding.Success && opts.StopOnValid {
			return findings
		}
	}

	if !opts.AnonOnly {
		runnable := 0
		for _, cred := range creds {
			if !redisCredentialRunnable(cred) {
				continue
			}
			runnable++
			finding := redisAttemptFunc(ctx, target, cred, "credential", opts.Timeout)
			findings = append(findings, finding)
			if finding.Success && opts.StopOnValid {
				break
			}
			if finding.Severity == core.SeverityError && ctx.Err() != nil {
				break
			}
		}
		if len(findings) == 0 && runnable == 0 {
			return []core.Finding{core.SkippedFinding(target, "credential", "no runnable authentication attempts for redis")}
		}
	}

	if len(findings) == 0 {
		return []core.Finding{core.SkippedFinding(target, "credential", "no runnable authentication attempts for redis")}
	}

	return findings
}

func checkRedisAttempt(ctx context.Context, target core.Target, cred core.Credential, authType string, timeout time.Duration) core.Finding {
	client, err := redisDialFunc(ctx, target, timeout)
	if err != nil {
		return core.ErrorFinding(target, authType, redisFindingUser(cred, ""), "", fmt.Sprintf("connect failed: %v", sanitizeRedisError(err)))
	}
	defer client.Close()

	notesPrefix := ""
	user := ""
	if authType == "credential" {
		outcome, authErr := redisAuthenticate(client, cred)
		user = outcome.displayUser
		notesPrefix = outcome.successPrefix
		if authErr != nil {
			if isRedisDeniedError(authErr) {
				return core.InvalidFinding(target, authType, user, "", "auth failed")
			}
			return core.ErrorFinding(target, authType, user, "", fmt.Sprintf("auth failed: %v", sanitizeRedisError(authErr)))
		}
	}

	pingResp, err := client.Do("PING")
	if err != nil {
		return core.ErrorFinding(target, authType, user, "", fmt.Sprintf("PING failed: %v", sanitizeRedisError(err)))
	}
	if pingResp.kind == '-' {
		if isRedisDeniedText(pingResp.text) {
			if authType == "anonymous" {
				return core.InvalidFinding(target, authType, "", "", "no-auth denied")
			}
			return core.InvalidFinding(target, authType, user, "", "auth failed")
		}
		return core.ErrorFinding(target, authType, user, "", fmt.Sprintf("PING failed: %s", normalizeEvidence(pingResp.text)))
	}
	if pingResp.kind != '+' || strings.ToUpper(strings.TrimSpace(pingResp.text)) != "PONG" {
		return core.ErrorFinding(target, authType, user, "", fmt.Sprintf("unexpected PING response: %s", normalizeEvidence(pingResp.text)))
	}

	infoResp, err := client.Do("INFO")
	if err != nil {
		return core.ErrorFinding(target, authType, user, "", fmt.Sprintf("INFO failed: %v", sanitizeRedisError(err)))
	}
	if infoResp.kind == '-' {
		if isRedisDeniedText(infoResp.text) {
			if authType == "anonymous" {
				return core.InvalidFinding(target, authType, "", "", "no-auth denied")
			}
			return core.InvalidFinding(target, authType, user, "", "auth failed")
		}
		return core.ErrorFinding(target, authType, user, "", fmt.Sprintf("INFO failed: %s", normalizeEvidence(infoResp.text)))
	}
	if infoResp.kind != '$' && infoResp.kind != '+' {
		return core.ErrorFinding(target, authType, user, "", "unexpected INFO response")
	}

	evidence := formatRedisInfoEvidence(infoResp.text)
	if evidence == "" {
		return core.ErrorFinding(target, authType, user, "", "INFO succeeded but returned no usable evidence")
	}

	notes := notesPrefix
	if authType == "anonymous" {
		notes = "no-auth"
	}

	return core.WithCredentialPassword(
		core.ValidFinding(target, authType, user, evidence, notes),
		cred.Password,
	)
}

func newRedisClient(ctx context.Context, target core.Target, timeout time.Duration) (redisClient, error) {
	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return &redisWireClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}, nil
}

func (c *redisWireClient) Close() error {
	return c.conn.Close()
}

func (c *redisWireClient) Do(args ...string) (redisResponse, error) {
	if len(args) == 0 {
		return redisResponse{}, errors.New("redis command requires at least one argument")
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("*%d\r\n", len(args)))
	for _, arg := range args {
		builder.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg))
	}

	if _, err := io.WriteString(c.conn, builder.String()); err != nil {
		return redisResponse{}, err
	}
	return c.readResponse()
}

func (c *redisWireClient) readResponse() (redisResponse, error) {
	prefix, err := c.reader.ReadByte()
	if err != nil {
		return redisResponse{}, err
	}

	switch prefix {
	case '+', '-', ':':
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return redisResponse{}, err
		}
		return redisResponse{kind: prefix, text: strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")}, nil
	case '$':
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return redisResponse{}, err
		}
		size, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			return redisResponse{}, fmt.Errorf("invalid redis bulk length %q", strings.TrimSpace(line))
		}
		if size < 0 {
			return redisResponse{kind: prefix, text: ""}, nil
		}
		payload := make([]byte, size+2)
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return redisResponse{}, err
		}
		return redisResponse{kind: prefix, text: string(payload[:size])}, nil
	default:
		return redisResponse{}, fmt.Errorf("unsupported redis response prefix %q", prefix)
	}
}

func redisAuthenticate(client redisClient, cred core.Credential) (redisAuthAttempt, error) {
	attempts := redisAuthAttempts(cred)
	if len(attempts) == 0 {
		return redisAuthAttempt{}, errors.New("no password provided")
	}

	var lastErr error
	for _, attempt := range attempts {
		var (
			resp redisResponse
			err  error
		)
		if attempt.passwordOnly {
			resp, err = client.Do("AUTH", attempt.password)
		} else {
			resp, err = client.Do("AUTH", attempt.username, attempt.password)
		}
		if err != nil {
			return attempt, err
		}
		if resp.kind == '+' && strings.EqualFold(strings.TrimSpace(resp.text), "OK") {
			return attempt, nil
		}
		if resp.kind == '-' {
			lastErr = errors.New(resp.text)
			if isRedisDeniedText(resp.text) {
				continue
			}
			return attempt, lastErr
		}
		lastErr = fmt.Errorf("unexpected AUTH response: %s", normalizeEvidence(resp.text))
		return attempt, lastErr
	}

	if lastErr == nil {
		lastErr = errors.New("authentication failed")
	}
	return attempts[0], lastErr
}

func redisCredentialRunnable(cred core.Credential) bool {
	return strings.TrimSpace(cred.Password) != ""
}

func redisAuthAttempts(cred core.Credential) []redisAuthAttempt {
	if !redisCredentialRunnable(cred) {
		return nil
	}

	display := displayUser(cred)
	attempts := make([]redisAuthAttempt, 0, 2)
	seen := make(map[string]struct{})
	add := func(attempt redisAuthAttempt) {
		key := attempt.username + "\x00" + attempt.password + "\x00" + strconv.FormatBool(attempt.passwordOnly)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		attempts = append(attempts, attempt)
	}

	if cred.Username != "" || cred.Domain != "" {
		add(redisAuthAttempt{
			username:    display,
			password:    cred.Password,
			displayUser: display,
		})
	}
	add(redisAuthAttempt{
		password:      cred.Password,
		passwordOnly:  true,
		displayUser:   "",
		successPrefix: "password-only auth",
	})

	return attempts
}

func redisFindingUser(cred core.Credential, fallback string) string {
	if fallback != "" {
		return fallback
	}
	if cred.Password != "" && cred.Username == "" && cred.Domain == "" {
		return ""
	}
	return displayUser(cred)
}

func isRedisDeniedError(err error) bool {
	if err == nil {
		return false
	}
	return isRedisDeniedText(err.Error())
}

func isRedisDeniedText(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "noauth") ||
		strings.Contains(lower, "wrongpass") ||
		strings.Contains(lower, "noperm") ||
		strings.Contains(lower, "authentication required") ||
		strings.Contains(lower, "invalid username-password pair") ||
		strings.Contains(lower, "auth failed")
}

func sanitizeRedisError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		return "connection closed by remote host"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return strings.Join(strings.Fields(err.Error()), " ")
}

func formatRedisInfoEvidence(info string) string {
	values := map[string]string{}
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		values[key] = normalizeEvidence(value)
	}

	parts := make([]string, 0, 3)
	if version := values["redis_version"]; version != "" {
		parts = append(parts, "redis_version="+version)
	}
	if role := values["role"]; role != "" {
		parts = append(parts, "role="+role)
	}
	for key, value := range values {
		if !strings.HasPrefix(key, "db") {
			continue
		}
		if keys, ok := parseRedisDBKeys(value); ok {
			parts = append(parts, fmt.Sprintf("%s_keys=%s", key, keys))
			break
		}
	}
	return strings.Join(parts, "; ")
}

func parseRedisDBKeys(raw string) (string, bool) {
	for _, part := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && key == "keys" {
			return value, true
		}
	}
	return "", false
}
