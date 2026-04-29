package modules

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

func TestNFSCheckRunsInAnonOnlyMode(t *testing.T) {
	original := nfsAttemptFunc
	t.Cleanup(func() { nfsAttemptFunc = original })

	called := 0
	nfsAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (nfsAttemptResult, error) {
		called++
		return nfsAttemptResult{exports: []string{"/srv/share"}, valid: true}, nil
	}

	mod := NewNFSModule()
	target := core.Target{Host: "10.10.10.100", Port: 2049, Proto: "tcp", Service: "nfs"}
	findings := mod.Check(context.Background(), target, []core.Credential{{Username: "user", Password: "Secret123!"}}, core.Options{
		AnonOnly: true,
		Timeout:  time.Second,
	})

	if called != 1 {
		t.Fatalf("expected one nfs attempt, got %d", called)
	}
	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "valid" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Username != "" {
		t.Fatalf("did not expect username in NFS finding: %+v", findings[0])
	}
}

func TestNFSCheckSkipsWhenAnonDisabled(t *testing.T) {
	mod := NewNFSModule()
	target := core.Target{Host: "10.10.10.101", Port: 2049, Proto: "tcp", Service: "nfs"}
	findings := mod.Check(context.Background(), target, nil, core.Options{
		IncludeAnon: false,
		Timeout:     time.Second,
	})

	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "skipped" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestNFSCheckNoCredentialLeakage(t *testing.T) {
	original := nfsAttemptFunc
	t.Cleanup(func() { nfsAttemptFunc = original })

	nfsAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (nfsAttemptResult, error) {
		return nfsAttemptResult{valid: true, exports: []string{"/backup"}}, nil
	}

	mod := NewNFSModule()
	target := core.Target{Host: "10.10.10.102", Port: 2049, Proto: "tcp", Service: "nfs"}
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

func TestNFSNoExportsVisibleIsInvalid(t *testing.T) {
	original := nfsAttemptFunc
	t.Cleanup(func() { nfsAttemptFunc = original })

	nfsAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (nfsAttemptResult, error) {
		return nfsAttemptResult{}, nil
	}

	mod := NewNFSModule()
	target := core.Target{Host: "10.10.10.103", Port: 2049, Proto: "tcp", Service: "nfs"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, Timeout: time.Second})

	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "invalid" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Notes != "no exports visible" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}

func TestNFSConnectionErrorIsError(t *testing.T) {
	original := nfsAttemptFunc
	t.Cleanup(func() { nfsAttemptFunc = original })

	nfsAttemptFunc = func(_ context.Context, _ core.Target, _ time.Duration) (nfsAttemptResult, error) {
		return nfsAttemptResult{}, context.DeadlineExceeded
	}

	mod := NewNFSModule()
	target := core.Target{Host: "10.10.10.104", Port: 2049, Proto: "tcp", Service: "nfs"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, Timeout: time.Second})

	if len(findings) != 1 || core.ClassifyFinding(findings[0]) != "error" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Notes != "timeout/no response" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}

func TestParseShowmountExports(t *testing.T) {
	raw := "Export list for 10.10.10.20:\n/srv/share *\n/backup 10.0.0.0/24\n"
	exports, access := parseShowmountExports(raw)
	if len(exports) != 2 || exports[0] != "/backup" || exports[1] != "/srv/share" {
		t.Fatalf("unexpected exports: %v", exports)
	}
	if access != "restricted" {
		t.Fatalf("expected restricted access, got %q", access)
	}
}

func TestSanitizeNFSError(t *testing.T) {
	if got := sanitizeNFSError(errors.New(" rpc mount export: timed out ")); got != "timeout/no response" {
		t.Fatalf("unexpected sanitized error: %q", got)
	}
}
