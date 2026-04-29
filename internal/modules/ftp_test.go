package modules

import (
	"context"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

func TestFTPCheckSummarizesAnonymousFailures(t *testing.T) {
	original := ftpAttemptFunc
	t.Cleanup(func() { ftpAttemptFunc = original })

	ftpAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, authType string, _ time.Duration) core.Finding {
		return core.InvalidFinding(target, authType, displayUser(cred), "", "530 Login incorrect")
	}

	mod := NewFTPModule()
	target := core.Target{Host: "10.10.10.5", Port: 21, Service: "ftp"}
	findings := mod.Check(context.Background(), target, nil, core.Options{
		IncludeAnon: true,
		StopOnValid: true,
		Timeout:     time.Second,
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 summarized finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "invalid" {
		t.Fatalf("expected invalid finding, got %q", got)
	}
	if findings[0].AuthType != "anonymous" {
		t.Fatalf("expected anonymous auth type, got %q", findings[0].AuthType)
	}
	if findings[0].Notes != "anonymous denied; tried anonymous:anonymous, anonymous:<blank>" {
		t.Fatalf("unexpected anonymous summary note: %q", findings[0].Notes)
	}
	if findings[0].Evidence != "tried anonymous variants: anonymous:anonymous, anonymous:<blank>" {
		t.Fatalf("unexpected anonymous summary evidence: %q", findings[0].Evidence)
	}
}

func TestFTPCheckReturnsSingleAnonymousValidFinding(t *testing.T) {
	original := ftpAttemptFunc
	t.Cleanup(func() { ftpAttemptFunc = original })

	ftpAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, authType string, _ time.Duration) core.Finding {
		if cred.Password == "" {
			return core.ValidFinding(target, authType, displayUser(cred), `banner=220 ftp; PWD=257 "/" is the current directory`, "ftp access confirmed via login and post-login command")
		}
		return core.InvalidFinding(target, authType, displayUser(cred), "", "530 Login incorrect")
	}

	mod := NewFTPModule()
	target := core.Target{Host: "10.10.10.5", Port: 21, Service: "ftp"}
	findings := mod.Check(context.Background(), target, nil, core.Options{
		IncludeAnon: true,
		StopOnValid: true,
		Timeout:     time.Second,
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 summarized finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "valid" {
		t.Fatalf("expected valid finding, got %q", got)
	}
	if !strings.Contains(findings[0].Evidence, "PWD=257") {
		t.Fatalf("expected proof evidence preserved, got %q", findings[0].Evidence)
	}
	if !strings.Contains(findings[0].Notes, "anonymous:<blank>") {
		t.Fatalf("expected successful variant in notes, got %q", findings[0].Notes)
	}
}

func TestFTPCheckKeepsCredentialFindingsUnchanged(t *testing.T) {
	original := ftpAttemptFunc
	t.Cleanup(func() { ftpAttemptFunc = original })

	ftpAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, authType string, _ time.Duration) core.Finding {
		if authType == "anonymous" {
			return core.InvalidFinding(target, authType, displayUser(cred), "", "530 Login incorrect")
		}
		return core.InvalidFinding(target, authType, displayUser(cred), "", "credential failed")
	}

	mod := NewFTPModule()
	target := core.Target{Host: "10.10.10.5", Port: 21, Service: "ftp"}
	creds := []core.Credential{{Username: "svc-backup", Password: "badpass"}}
	findings := mod.Check(context.Background(), target, creds, core.Options{
		IncludeAnon: true,
		StopOnValid: true,
		Timeout:     time.Second,
	})

	if len(findings) != 2 {
		t.Fatalf("expected anonymous summary plus credential finding, got %d", len(findings))
	}
	if findings[0].AuthType != "anonymous" {
		t.Fatalf("expected anonymous summary first, got %q", findings[0].AuthType)
	}
	if findings[1].AuthType != "credential" || findings[1].Username != "svc-backup" {
		t.Fatalf("expected credential finding preserved, got %+v", findings[1])
	}
	if findings[1].Notes != "credential failed" {
		t.Fatalf("expected unchanged credential note, got %q", findings[1].Notes)
	}
	if strings.Contains(findings[1].Notes, "badpass") || strings.Contains(findings[1].Evidence, "badpass") {
		t.Fatalf("password leaked in credential finding: %+v", findings[1])
	}
}
