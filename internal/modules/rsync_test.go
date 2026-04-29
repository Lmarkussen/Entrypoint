package modules

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

func TestRsyncCheckRunsInAnonOnlyMode(t *testing.T) {
	original := rsyncAttemptFunc
	t.Cleanup(func() { rsyncAttemptFunc = original })

	called := 0
	rsyncAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (rsyncAttemptResult, error) {
		called++
		return rsyncAttemptResult{modules: []string{"backup", "www"}, valid: true}, nil
	}

	mod := NewRsyncModule()
	target := core.Target{Host: "10.10.10.110", Port: 873, Proto: "tcp", Service: "rsync"}
	findings := mod.Check(context.Background(), target, []core.Credential{{Username: "user", Password: "Secret123!"}}, core.Options{
		AnonOnly: true,
		Timeout:  time.Second,
	})

	if called != 1 {
		t.Fatalf("expected one rsync attempt, got %d", called)
	}
	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "valid" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Username != "" {
		t.Fatalf("did not expect username in rsync finding: %+v", findings[0])
	}
}

func TestRsyncCheckSkipsWhenAnonDisabled(t *testing.T) {
	mod := NewRsyncModule()
	target := core.Target{Host: "10.10.10.111", Port: 873, Proto: "tcp", Service: "rsync"}
	findings := mod.Check(context.Background(), target, nil, core.Options{
		IncludeAnon: false,
		Timeout:     time.Second,
	})

	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "skipped" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestRsyncCheckNoCredentialLeakage(t *testing.T) {
	original := rsyncAttemptFunc
	t.Cleanup(func() { rsyncAttemptFunc = original })

	rsyncAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (rsyncAttemptResult, error) {
		return rsyncAttemptResult{valid: true, modules: []string{"backup"}}, nil
	}

	mod := NewRsyncModule()
	target := core.Target{Host: "10.10.10.112", Port: 873, Proto: "tcp", Service: "rsync"}
	findings := mod.Check(context.Background(), target, []core.Credential{{Username: "user", Password: "Secret123!"}}, core.Options{
		IncludeAnon: true,
		Timeout:     time.Second,
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if strings.Contains(findings[0].Notes, "Secret123!") || strings.Contains(findings[0].Evidence, "Secret123!") {
		t.Fatalf("password leaked in finding: %+v", findings[0])
	}
}

func TestRsyncNoModulesVisibleIsInvalid(t *testing.T) {
	original := rsyncAttemptFunc
	t.Cleanup(func() { rsyncAttemptFunc = original })

	rsyncAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (rsyncAttemptResult, error) {
		return rsyncAttemptResult{}, nil
	}

	mod := NewRsyncModule()
	target := core.Target{Host: "10.10.10.113", Port: 873, Proto: "tcp", Service: "rsync"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, Timeout: time.Second})

	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "invalid" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Notes != "no modules visible" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}

func TestRsyncDeniedListingIsInvalid(t *testing.T) {
	original := rsyncAttemptFunc
	t.Cleanup(func() { rsyncAttemptFunc = original })

	rsyncAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (rsyncAttemptResult, error) {
		return rsyncAttemptResult{}, errors.New("@ERROR: module list disabled")
	}

	mod := NewRsyncModule()
	target := core.Target{Host: "10.10.10.114", Port: 873, Proto: "tcp", Service: "rsync"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, Timeout: time.Second})

	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "invalid" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestRsyncConnectionErrorIsError(t *testing.T) {
	original := rsyncAttemptFunc
	t.Cleanup(func() { rsyncAttemptFunc = original })

	rsyncAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (rsyncAttemptResult, error) {
		return rsyncAttemptResult{}, context.DeadlineExceeded
	}

	mod := NewRsyncModule()
	target := core.Target{Host: "10.10.10.115", Port: 873, Proto: "tcp", Service: "rsync"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, Timeout: time.Second})

	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "error" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Notes != "timeout/no response" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}

func TestParseRsyncModules(t *testing.T) {
	raw := "@RSYNCD: 31.0\nbackup\tbackup module\nwww\twebsite module\nbackup\tduplicate module\n"
	modules := parseRsyncModules(raw)
	if len(modules) != 2 || modules[0] != "backup" || modules[1] != "www" {
		t.Fatalf("unexpected modules: %v", modules)
	}
}

func TestSanitizeRsyncInvalid(t *testing.T) {
	if got := sanitizeRsyncInvalid(errors.New("@ERROR: module list disabled")); got != "no modules visible" {
		t.Fatalf("unexpected sanitized invalid error: %q", got)
	}
}

func TestSanitizeRsyncError(t *testing.T) {
	if got := sanitizeRsyncError(errors.New(" connection timed out ")); got != "timeout/no response" {
		t.Fatalf("unexpected sanitized error: %q", got)
	}
}
