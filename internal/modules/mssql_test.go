package modules

import (
	"context"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

func TestMSSQLCheckSkipsAnonOnly(t *testing.T) {
	mod := NewMSSQLModule()
	target := core.Target{Host: "10.10.10.80", Port: 1433, Proto: "tcp", Service: "mssql"}

	findings := mod.Check(context.Background(), target, nil, core.Options{AnonOnly: true, Timeout: time.Second})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "skipped" {
		t.Fatalf("expected skipped, got %q", got)
	}
	if findings[0].Notes != "anon-only mode; mssql has no anonymous auth" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}

func TestMSSQLCheckRequiresCreds(t *testing.T) {
	mod := NewMSSQLModule()
	target := core.Target{Host: "10.10.10.81", Port: 1433, Proto: "tcp", Service: "mssql"}

	findings := mod.Check(context.Background(), target, nil, core.Options{Timeout: time.Second})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "skipped" {
		t.Fatalf("expected skipped, got %q", got)
	}
	if findings[0].Notes != "no credentials supplied for mssql" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}

func TestMSSQLCheckDoesNotLeakPassword(t *testing.T) {
	original := mssqlAttemptFunc
	t.Cleanup(func() { mssqlAttemptFunc = original })

	mssqlAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, _ time.Duration) core.Finding {
		return core.InvalidFinding(target, "credential", displayUser(cred), "", "login failed")
	}

	mod := NewMSSQLModule()
	target := core.Target{Host: "10.10.10.82", Port: 1433, Proto: "tcp", Service: "mssql"}
	creds := []core.Credential{{Username: "admin", Password: "Secret123!"}}
	findings := mod.Check(context.Background(), target, creds, core.Options{Timeout: time.Second})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if strings.Contains(findings[0].Notes, "Secret123!") || strings.Contains(findings[0].Evidence, "Secret123!") {
		t.Fatalf("password leaked in finding: %+v", findings[0])
	}
}

func TestMSSQLLoginCandidates(t *testing.T) {
	got := mssqlLoginCandidates(core.Credential{Domain: "corp.local", Username: "svc-sql", Password: "x"})
	want := []string{`corp.local\svc-sql`, "svc-sql@corp.local", "svc-sql"}
	if len(got) != len(want) {
		t.Fatalf("unexpected candidates: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected candidates: got %v want %v", got, want)
		}
	}
}
