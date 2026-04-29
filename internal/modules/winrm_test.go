package modules

import (
	"context"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

func TestWinRMCheckSkipsAnonOnly(t *testing.T) {
	mod := NewWinRMModule()
	target := core.Target{Host: "10.10.10.70", Port: 5985, Proto: "tcp", Service: "winrm"}

	findings := mod.Check(context.Background(), target, nil, core.Options{AnonOnly: true, Timeout: time.Second})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "skipped" {
		t.Fatalf("expected skipped finding, got %q", got)
	}
	if findings[0].Notes != "anon-only mode; winrm has no anonymous auth" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}

func TestWinRMCheckCredentialFindingKeepsUsernameWithoutPassword(t *testing.T) {
	original := winrmAttemptFunc
	t.Cleanup(func() { winrmAttemptFunc = original })

	winrmAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, _ winrmAttemptOptions) core.Finding {
		return core.InvalidFinding(target, "credential", displayUser(cred), "", "login failed")
	}

	mod := NewWinRMModule()
	target := core.Target{Host: "10.10.10.71", Port: 5985, Proto: "tcp", Service: "winrm"}
	creds := []core.Credential{{Domain: "CORP", Username: "test", Password: "Secret123!"}}
	findings := mod.Check(context.Background(), target, creds, core.Options{Timeout: time.Second, StopOnValid: true})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Username != `CORP\test` {
		t.Fatalf("unexpected username: %q", findings[0].Username)
	}
	if strings.Contains(findings[0].Notes, "Secret123!") || strings.Contains(findings[0].Evidence, "Secret123!") {
		t.Fatalf("password leaked in finding: %+v", findings[0])
	}
}

func TestFormatWinRMWhoami(t *testing.T) {
	raw := "Microsoft Windows [Version 10.0.17763.0]\r\n\r\ncorp\\test\r\n"
	got := formatWinRMWhoami(raw)
	if got != `corp\test` {
		t.Fatalf("expected concise whoami result, got %q", got)
	}
}

func TestWinRMAuthCandidates(t *testing.T) {
	got := winrmAuthCandidates(core.Credential{Domain: "corp.local", Username: "test", Password: "x"})
	want := []string{`corp.local\test`, "test@corp.local", "test"}
	if len(got) != len(want) {
		t.Fatalf("unexpected candidates: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected candidates: got %v want %v", got, want)
		}
	}
}
