package modules

import (
	"context"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

type fakeLDAPClient struct {
	bindErr    map[string]error
	rootDSE    map[string][]string
	rootDSEErr error
	bindCalls  []string
}

func (f *fakeLDAPClient) Close() error { return nil }

func (f *fakeLDAPClient) Bind(username, _ string) error {
	f.bindCalls = append(f.bindCalls, username)
	if f.bindErr == nil {
		return nil
	}
	return f.bindErr[username]
}

func (f *fakeLDAPClient) RootDSE() (map[string][]string, error) {
	return f.rootDSE, f.rootDSEErr
}

func TestLDAPCheckSkipsCredentialsInAnonOnly(t *testing.T) {
	original := ldapAttemptFunc
	t.Cleanup(func() { ldapAttemptFunc = original })

	var authTypes []string
	ldapAttemptFunc = func(_ context.Context, target core.Target, cred core.Credential, authType string, _ ldapAttemptOptions) core.Finding {
		authTypes = append(authTypes, authType)
		return core.InvalidFinding(target, authType, displayUser(cred), "", "denied")
	}

	mod := NewLDAPModule()
	target := core.Target{Host: "10.10.10.50", Port: 389, Service: "ldap"}
	creds := []core.Credential{{Username: "user", Password: "secret"}}
	findings := mod.Check(context.Background(), target, creds, core.Options{AnonOnly: true, IncludeAnon: true, Timeout: time.Second})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(authTypes) != 1 || authTypes[0] != "anonymous" {
		t.Fatalf("expected only anonymous attempt, got %v", authTypes)
	}
}

func TestLDAPCheckCredentialFindingKeepsUsernameWithoutPassword(t *testing.T) {
	originalDial := ldapDialFunc
	t.Cleanup(func() { ldapDialFunc = originalDial })

	client := &fakeLDAPClient{
		bindErr: map[string]error{
			`CORP\svc-backup`: &ldapError{code: ldapResultInvalidCreds, stage: "bind", message: "invalid credentials"},
			"svc-backup":      &ldapError{code: ldapResultInvalidCreds, stage: "bind", message: "invalid credentials"},
		},
	}
	ldapDialFunc = func(core.Target, ldapAttemptOptions) (ldapClient, error) {
		return client, nil
	}

	finding := checkLDAPAttempt(context.Background(), core.Target{Host: "10.10.10.60", Port: 389, Service: "ldap"}, core.Credential{
		Domain:   "CORP",
		Username: "svc-backup",
		Password: "Secret123!",
	}, "credential", ldapAttemptOptions{timeout: time.Second})

	if got := core.ClassifyFinding(finding); got != "invalid" {
		t.Fatalf("expected invalid finding, got %q", got)
	}
	if finding.Username != `CORP\svc-backup` {
		t.Fatalf("unexpected username: %q", finding.Username)
	}
	if strings.Contains(finding.Notes, "Secret123!") || strings.Contains(finding.Evidence, "Secret123!") {
		t.Fatalf("password leaked in finding: %+v", finding)
	}
}

func TestLDAPAnonymousValidRequiresRootDSEProof(t *testing.T) {
	originalDial := ldapDialFunc
	t.Cleanup(func() { ldapDialFunc = originalDial })

	client := &fakeLDAPClient{
		rootDSE: map[string][]string{
			"defaultNamingContext": {"DC=corp,DC=local"},
		},
	}
	ldapDialFunc = func(core.Target, ldapAttemptOptions) (ldapClient, error) {
		return client, nil
	}

	finding := checkLDAPAttempt(context.Background(), core.Target{Host: "10.10.10.61", Port: 389, Service: "ldap"}, core.Credential{}, "anonymous", ldapAttemptOptions{timeout: time.Second})
	if got := core.ClassifyFinding(finding); got != "valid" {
		t.Fatalf("expected valid finding, got %q", got)
	}
	if !strings.Contains(finding.Notes, "anonymous bind + RootDSE query successful") {
		t.Fatalf("unexpected note: %q", finding.Notes)
	}
	if !strings.Contains(finding.Evidence, "defaultNamingContext=DC=corp,DC=local") {
		t.Fatalf("unexpected evidence: %q", finding.Evidence)
	}
}

func TestLDAPQueryDeniedAfterBindIsInvalid(t *testing.T) {
	originalDial := ldapDialFunc
	t.Cleanup(func() { ldapDialFunc = originalDial })

	client := &fakeLDAPClient{
		rootDSEErr: &ldapError{code: ldapResultAccessDenied, stage: "rootdse", message: "access denied"},
	}
	ldapDialFunc = func(core.Target, ldapAttemptOptions) (ldapClient, error) {
		return client, nil
	}

	finding := checkLDAPAttempt(context.Background(), core.Target{Host: "10.10.10.62", Port: 636, Service: "ldaps"}, core.Credential{
		Username: "user@corp.local",
		Password: "Secret123!",
	}, "credential", ldapAttemptOptions{useTLS: true, timeout: time.Second})

	if got := core.ClassifyFinding(finding); got != "invalid" {
		t.Fatalf("expected invalid finding, got %q", got)
	}
	if finding.Notes != "bind succeeded but RootDSE query denied" {
		t.Fatalf("unexpected note: %q", finding.Notes)
	}
}

func TestLDAPBindCandidates(t *testing.T) {
	candidates := ldapBindCandidates(core.Credential{Domain: "corp.local", Username: "test", Password: "x"})
	want := []string{`corp.local\test`, "test@corp.local", "test"}

	if len(candidates) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %v", len(want), len(candidates), candidates)
	}
	for i := range want {
		if candidates[i] != want[i] {
			t.Fatalf("unexpected candidates: got %v want %v", candidates, want)
		}
	}
}
