package modules

import (
	"context"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
	"github.com/hirochachacha/go-smb2"
)

func TestSMBCheckSkipsPort139(t *testing.T) {
	mod := NewSMBModule()
	target := core.Target{Host: "10.10.10.10", Port: 139, Service: "smb"}

	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, Timeout: time.Second})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "skipped" {
		t.Fatalf("expected skipped finding, got %q", got)
	}
}

func TestSMBCheckSummarizesNullSessionDenial(t *testing.T) {
	original := smbAttemptFunc
	t.Cleanup(func() { smbAttemptFunc = original })

	smbAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, authType string, _ time.Duration) core.Finding {
		return core.InvalidFinding(target, authType, displayUser(cred), "", smbInvalidAuthNote(authType))
	}

	mod := NewSMBModule()
	target := core.Target{Host: "10.10.10.20", Port: 445, Service: "smb"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, StopOnValid: true, Timeout: time.Second})

	if len(findings) != 1 {
		t.Fatalf("expected 1 summarized finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "invalid" {
		t.Fatalf("expected invalid finding, got %q", got)
	}
	if findings[0].Notes != "null session denied" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
	if findings[0].Evidence != "tried <empty>:<blank>, Guest:<blank>" {
		t.Fatalf("unexpected evidence: %q", findings[0].Evidence)
	}
}

func TestSMBCheckReturnsNullSessionValidFinding(t *testing.T) {
	original := smbAttemptFunc
	t.Cleanup(func() { smbAttemptFunc = original })

	smbAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, authType string, _ time.Duration) core.Finding {
		if cred.Username == "" {
			return core.ValidFinding(target, authType, displayUser(cred), "", "null session confirmed; shares=IPC$,NETLOGON")
		}
		return core.InvalidFinding(target, authType, displayUser(cred), "", smbInvalidAuthNote(authType))
	}

	mod := NewSMBModule()
	target := core.Target{Host: "10.10.10.20", Port: 445, Service: "smb"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, StopOnValid: true, Timeout: time.Second})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "valid" {
		t.Fatalf("expected valid finding, got %q", got)
	}
	if !strings.Contains(findings[0].Notes, "shares=IPC$,NETLOGON") {
		t.Fatalf("expected share evidence, got %q", findings[0].Notes)
	}
}

func TestSMBCheckCredentialFindingsIncludeUsername(t *testing.T) {
	original := smbAttemptFunc
	t.Cleanup(func() { smbAttemptFunc = original })

	smbAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, authType string, _ time.Duration) core.Finding {
		if authType == "credential" {
			return core.ValidFinding(target, authType, displayUser(cred), "", "shares=SYSVOL,NETLOGON")
		}
		return core.InvalidFinding(target, authType, displayUser(cred), "", smbInvalidAuthNote(authType))
	}

	mod := NewSMBModule()
	target := core.Target{Host: "10.10.10.21", Port: 445, Service: "smb"}
	creds := []core.Credential{{Domain: "CORP", Username: "svc-backup", Password: "secret"}}
	findings := mod.Check(context.Background(), target, creds, core.Options{
		IncludeAnon: true,
		StopOnValid: true,
		Timeout:     time.Second,
	})

	if len(findings) != 2 {
		t.Fatalf("expected null-session summary plus credential finding, got %d", len(findings))
	}
	if findings[1].AuthType != "credential" || findings[1].Username != `CORP\svc-backup` {
		t.Fatalf("unexpected credential finding: %+v", findings[1])
	}
	if strings.Contains(findings[1].Notes, "secret") || strings.Contains(findings[1].Evidence, "secret") {
		t.Fatalf("password leaked in credential finding: %+v", findings[1])
	}
}

func TestSMBSanitizeInvalidAuthCodesOnly(t *testing.T) {
	respDenied := &smb2.ResponseError{Code: smbStatusLogonFailure}
	respOther := &smb2.ResponseError{Code: 0xC0000008}

	if !isSMBInvalidAuth(respDenied, "credential") {
		t.Fatal("expected logon failure to be classified as invalid auth")
	}
	if isSMBInvalidAuth(respOther, "credential") {
		t.Fatal("expected unrelated response error to remain non-auth error")
	}
}
