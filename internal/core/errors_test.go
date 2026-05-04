package core

import "testing"

func TestNormalizeOperatorErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "operation not permitted", in: "connect failed: dial tcp 10.0.0.1:22: socket: operation not permitted", want: "local socket blocked / operation not permitted"},
		{name: "connection refused", in: "connect failed: dial tcp 10.0.0.1:22: connect: connection refused", want: "connection refused"},
		{name: "timeout", in: "connect failed: dial tcp 10.0.0.1:22: i/o timeout", want: "timeout"},
		{name: "deadline exceeded", in: "context deadline exceeded", want: "timeout"},
		{name: "no route", in: "connect failed: dial tcp 10.0.0.1:22: no route to host", want: "no route to host"},
		{name: "network unreachable", in: "connect failed: dial tcp 10.0.0.1:22: network is unreachable", want: "network unreachable"},
		{name: "connection reset", in: "ssh handshake failed: read tcp 10.0.0.2:1234->10.0.0.1:22: read: connection reset by peer", want: "connection reset"},
		{name: "closed before prompt", in: "timeout waiting for login prompt: EOF", want: "connection closed before prompt"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeOperatorErrorMessage(tc.in); got != tc.want {
				t.Fatalf("normalizeOperatorErrorMessage(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeFindingErrorClearsPasswordOnError(t *testing.T) {
	finding := ErrorFinding(Target{Host: "10.10.10.1", Port: 22, Service: "ssh"}, "credential", "test", "", "connect failed: dial tcp 10.10.10.1:22: socket: operation not permitted")
	finding.Password = "Secret123!"

	got := NormalizeFindingError(finding)
	if got.Password != "" {
		t.Fatalf("expected password cleared on error finding, got %q", got.Password)
	}
	if got.Notes != "local socket blocked / operation not permitted" {
		t.Fatalf("unexpected normalized note: %q", got.Notes)
	}
}

func TestNormalizeAndCollapseFindingsCollapsesRepeatedConnectionErrors(t *testing.T) {
	target := Target{Host: "10.10.10.1", Port: 389, Service: "ldap"}
	findings := []Finding{
		ErrorFinding(target, "anonymous", "", "", "connect failed: dial tcp 10.10.10.1:389: socket: operation not permitted"),
		ErrorFinding(target, "credential", "lars", "", "connect failed: dial tcp 10.10.10.1:389: socket: operation not permitted"),
		ErrorFinding(target, "credential", "test", "", "connect failed: dial tcp 10.10.10.1:389: socket: operation not permitted"),
	}

	got := NormalizeAndCollapseFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 collapsed finding, got %d: %+v", len(got), got)
	}
	if got[0].AuthType != AuthTypeInfrastructure {
		t.Fatalf("expected infrastructure auth type, got %q", got[0].AuthType)
	}
	if got[0].Username != "" || got[0].Password != "" {
		t.Fatalf("expected collapsed error without credentials, got %+v", got[0])
	}
	if got[0].Notes != "local socket blocked / operation not permitted" {
		t.Fatalf("unexpected collapsed note: %q", got[0].Notes)
	}
}

func TestNormalizeAndCollapseFindingsDoesNotCollapseInvalidAuthFailures(t *testing.T) {
	target := Target{Host: "10.10.10.2", Port: 22, Service: "ssh"}
	findings := []Finding{
		InvalidFinding(target, "credential", "lars", "", "login failed"),
		InvalidFinding(target, "credential", "test", "", "login failed"),
	}

	got := NormalizeAndCollapseFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected invalid findings not collapsed, got %d: %+v", len(got), got)
	}
}

func TestNormalizeAndCollapseFindingsSummarizesRepeatedInvalidCredentialFailures(t *testing.T) {
	target := Target{Host: "10.10.10.20", Port: 22, Service: "ssh"}
	findings := []Finding{
		InvalidFinding(target, "credential", "admin", "Linux banner\nlogin:", "login failed"),
		InvalidFinding(target, "credential", "admin", "", "Login incorrect"),
		InvalidFinding(target, "credential", "admin", "", "invalid credentials"),
	}

	got := NormalizeAndCollapseFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 summarized invalid finding, got %d: %+v", len(got), got)
	}
	if got[0].Notes != "login failed; tried 3 passwords" {
		t.Fatalf("unexpected summarized note: %q", got[0].Notes)
	}
	if got[0].Password != "" {
		t.Fatalf("unexpected password leakage in summarized invalid finding: %+v", got[0])
	}
	if got[0].Evidence != "" {
		t.Fatalf("expected summarized invalid evidence cleared, got %+v", got[0])
	}
}

func TestNormalizeAndCollapseFindingsSuppressesRepeatedInvalidsWhenValidExistsForSameUser(t *testing.T) {
	target := Target{Host: "10.10.10.21", Port: 22, Service: "ssh"}
	findings := []Finding{
		InvalidFinding(target, "credential", "admin", "", "login failed"),
		InvalidFinding(target, "credential", "admin", "", "login failed"),
		WithCredentialPassword(ValidFinding(target, "credential", "admin", "whoami => admin", "ssh access confirmed"), "Secret123!"),
	}

	got := NormalizeAndCollapseFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected only valid finding retained, got %d: %+v", len(got), got)
	}
	if !got[0].Success || got[0].Username != "admin" {
		t.Fatalf("unexpected remaining finding: %+v", got[0])
	}
}

func TestNormalizeAndCollapseFindingsKeepsDistinctFailureReasonsVisible(t *testing.T) {
	target := Target{Host: "10.10.10.22", Port: 22, Service: "ssh"}
	findings := []Finding{
		InvalidFinding(target, "credential", "admin", "", "login failed"),
		InvalidFinding(target, "credential", "admin", "", "account locked"),
	}

	got := NormalizeAndCollapseFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected distinct failure reasons retained, got %d: %+v", len(got), got)
	}
}

func TestNormalizeAndCollapseFindingsDoesNotMergeDifferentDomainsOrServices(t *testing.T) {
	sshTarget := Target{Host: "10.10.10.23", Port: 22, Service: "ssh"}
	smbTarget := Target{Host: "10.10.10.23", Port: 445, Service: "smb"}
	findings := []Finding{
		InvalidFinding(sshTarget, "credential", `CORP\admin`, "", "login failed"),
		InvalidFinding(sshTarget, "credential", `CORP\admin`, "", "login failed"),
		InvalidFinding(sshTarget, "credential", `DEV\admin`, "", "login failed"),
		InvalidFinding(sshTarget, "credential", `DEV\admin`, "", "login failed"),
		InvalidFinding(smbTarget, "credential", `CORP\admin`, "", "login failed"),
		InvalidFinding(smbTarget, "credential", `CORP\admin`, "", "login failed"),
	}

	got := NormalizeAndCollapseFindings(findings)
	if len(got) != 3 {
		t.Fatalf("expected 3 separate summarized findings, got %d: %+v", len(got), got)
	}
}

func TestNormalizeAndCollapseFindingsDoesNotHideValidFindings(t *testing.T) {
	target := Target{Host: "10.10.10.3", Port: 22, Service: "ssh"}
	findings := []Finding{
		WithCredentialPassword(ValidFinding(target, "credential", "lars", "whoami => lars", "ssh access confirmed"), "Secret123!"),
		ErrorFinding(target, "credential", "test", "", "connect failed: dial tcp 10.10.10.3:22: connection refused"),
	}

	got := NormalizeAndCollapseFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected valid finding retained, got %d: %+v", len(got), got)
	}
	if !got[0].Success {
		t.Fatalf("expected valid finding preserved, got %+v", got[0])
	}
}
