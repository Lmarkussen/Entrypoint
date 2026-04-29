package modules

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

type fakeRedisClient struct {
	responses []redisResponse
	errs      []error
	index     int
}

func (c *fakeRedisClient) Close() error { return nil }

func (c *fakeRedisClient) Do(_ ...string) (redisResponse, error) {
	if c.index < len(c.errs) && c.errs[c.index] != nil {
		err := c.errs[c.index]
		c.index++
		return redisResponse{}, err
	}
	if c.index >= len(c.responses) {
		return redisResponse{}, errors.New("unexpected redis command")
	}
	resp := c.responses[c.index]
	c.index++
	return resp, nil
}

func TestRedisCheckRunsInAnonOnlyMode(t *testing.T) {
	original := redisAttemptFunc
	t.Cleanup(func() { redisAttemptFunc = original })

	called := 0
	redisAttemptFunc = func(_ context.Context, target core.Target, _ core.Credential, authType string, _ time.Duration) core.Finding {
		called++
		if authType != "anonymous" {
			t.Fatalf("expected anonymous auth type, got %q", authType)
		}
		return core.InvalidFinding(target, "anonymous", "", "", "no-auth denied")
	}

	mod := NewRedisModule()
	target := core.Target{Host: "10.10.10.90", Port: 6379, Proto: "tcp", Service: "redis"}
	findings := mod.Check(context.Background(), target, []core.Credential{{Username: "default", Password: "secret"}}, core.Options{
		AnonOnly: true,
		Timeout:  time.Second,
	})

	if called != 1 {
		t.Fatalf("expected one anonymous attempt, got %d", called)
	}
	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "invalid" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestRedisCheckSupportsCredentialMode(t *testing.T) {
	original := redisAttemptFunc
	t.Cleanup(func() { redisAttemptFunc = original })

	redisAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, authType string, _ time.Duration) core.Finding {
		if authType == "credential" {
			return core.ValidFinding(target, "credential", displayUser(cred), "redis_version=7.0.15; role=master", "")
		}
		return core.InvalidFinding(target, "anonymous", "", "", "no-auth denied")
	}

	mod := NewRedisModule()
	target := core.Target{Host: "10.10.10.91", Port: 6379, Proto: "tcp", Service: "redis"}
	findings := mod.Check(context.Background(), target, []core.Credential{{Username: "default", Password: "secret"}}, core.Options{
		IncludeAnon: false,
		Timeout:     time.Second,
	})

	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "valid" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Username != "default" {
		t.Fatalf("unexpected username: %q", findings[0].Username)
	}
}

func TestRedisCheckDoesNotLeakPassword(t *testing.T) {
	original := redisAttemptFunc
	t.Cleanup(func() { redisAttemptFunc = original })

	redisAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, _ string, _ time.Duration) core.Finding {
		return core.InvalidFinding(target, "credential", displayUser(cred), "", "auth failed")
	}

	mod := NewRedisModule()
	target := core.Target{Host: "10.10.10.92", Port: 6379, Proto: "tcp", Service: "redis"}
	findings := mod.Check(context.Background(), target, []core.Credential{{Username: "default", Password: "Secret123!"}}, core.Options{
		IncludeAnon: false,
		Timeout:     time.Second,
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if strings.Contains(findings[0].Notes, "Secret123!") || strings.Contains(findings[0].Evidence, "Secret123!") {
		t.Fatalf("password leaked in finding: %+v", findings[0])
	}
}

func TestCheckRedisAttemptNoAuthDeniedIsInvalid(t *testing.T) {
	original := redisDialFunc
	t.Cleanup(func() { redisDialFunc = original })

	redisDialFunc = func(context.Context, core.Target, time.Duration) (redisClient, error) {
		return &fakeRedisClient{responses: []redisResponse{{kind: '-', text: "NOAUTH Authentication required."}}}, nil
	}

	target := core.Target{Host: "10.10.10.93", Port: 6379, Proto: "tcp", Service: "redis"}
	finding := checkRedisAttempt(context.Background(), target, core.Credential{}, "anonymous", time.Second)

	if got := core.ClassifyFinding(finding); got != "invalid" {
		t.Fatalf("expected invalid finding, got %q", got)
	}
	if finding.Notes != "no-auth denied" {
		t.Fatalf("unexpected note: %q", finding.Notes)
	}
}

func TestCheckRedisAttemptConnectionErrorIsError(t *testing.T) {
	original := redisDialFunc
	t.Cleanup(func() { redisDialFunc = original })

	redisDialFunc = func(context.Context, core.Target, time.Duration) (redisClient, error) {
		return nil, context.DeadlineExceeded
	}

	target := core.Target{Host: "10.10.10.94", Port: 6379, Proto: "tcp", Service: "redis"}
	finding := checkRedisAttempt(context.Background(), target, core.Credential{}, "anonymous", time.Second)

	if got := core.ClassifyFinding(finding); got != "error" {
		t.Fatalf("expected error finding, got %q", got)
	}
	if !strings.Contains(finding.Notes, "connect failed: timeout") {
		t.Fatalf("unexpected note: %q", finding.Notes)
	}
}

func TestCheckRedisAttemptValidCredentialProof(t *testing.T) {
	original := redisDialFunc
	t.Cleanup(func() { redisDialFunc = original })

	redisDialFunc = func(context.Context, core.Target, time.Duration) (redisClient, error) {
		return &fakeRedisClient{
			responses: []redisResponse{
				{kind: '+', text: "OK"},
				{kind: '+', text: "PONG"},
				{kind: '$', text: "# Server\r\nredis_version:7.0.15\r\n# Replication\r\nrole:master\r\n# Keyspace\r\ndb0:keys=12,expires=0,avg_ttl=0\r\n"},
			},
		}, nil
	}

	target := core.Target{Host: "10.10.10.95", Port: 6379, Proto: "tcp", Service: "redis"}
	finding := checkRedisAttempt(context.Background(), target, core.Credential{Username: "default", Password: "secret"}, "credential", time.Second)

	if got := core.ClassifyFinding(finding); got != "valid" {
		t.Fatalf("expected valid finding, got %q", got)
	}
	if !strings.Contains(finding.Evidence, "redis_version=7.0.15") || !strings.Contains(finding.Evidence, "role=master") {
		t.Fatalf("unexpected evidence: %q", finding.Evidence)
	}
}

func TestRedisAuthAttemptsIncludePasswordOnlyFallback(t *testing.T) {
	attempts := redisAuthAttempts(core.Credential{Username: "default", Password: "secret"})
	if len(attempts) != 2 {
		t.Fatalf("expected 2 auth attempts, got %d", len(attempts))
	}
	if attempts[0].username != "default" || attempts[0].passwordOnly {
		t.Fatalf("unexpected first attempt: %+v", attempts[0])
	}
	if !attempts[1].passwordOnly || attempts[1].displayUser != "" {
		t.Fatalf("unexpected second attempt: %+v", attempts[1])
	}
}
