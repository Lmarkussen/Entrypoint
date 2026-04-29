package modules

import (
	"context"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

func TestSSHCheckSkipsAnonOnly(t *testing.T) {
	mod := NewSSHModule()
	target := core.Target{Host: "10.10.10.40", Port: 22, Service: "ssh"}

	findings := mod.Check(context.Background(), target, nil, core.Options{AnonOnly: true, Timeout: time.Second})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "skipped" {
		t.Fatalf("expected skipped finding, got %q", got)
	}
}

func TestSSHCheckCredentialFindingKeepsUsernameWithoutPassword(t *testing.T) {
	original := sshAttemptFunc
	t.Cleanup(func() { sshAttemptFunc = original })

	sshAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, _ time.Duration) core.Finding {
		return core.InvalidFinding(target, "credential", displayUser(cred), "", "login failed")
	}

	mod := NewSSHModule()
	target := core.Target{Host: "10.10.10.41", Port: 22, Service: "ssh"}
	creds := []core.Credential{{Domain: "CORP", Username: "svc-backup", Password: "Secret123!"}}
	findings := mod.Check(context.Background(), target, creds, core.Options{Timeout: time.Second, StopOnValid: true})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Username != `CORP\svc-backup` {
		t.Fatalf("unexpected username: %q", findings[0].Username)
	}
	if strings.Contains(findings[0].Notes, "Secret123!") || strings.Contains(findings[0].Evidence, "Secret123!") {
		t.Fatalf("password leaked in finding: %+v", findings[0])
	}
}

func TestFormatSSHProofEvidenceWhoami(t *testing.T) {
	raw := "Welcome to Ubuntu\nLast login: Tue Apr 29 11:00:00 2026\ntest\n"
	got := formatSSHProofEvidence(raw, "whoami")
	if got != "test" {
		t.Fatalf("expected concise whoami result, got %q", got)
	}
}
