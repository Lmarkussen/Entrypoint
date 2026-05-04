package parser

import (
	"strings"
	"testing"

	"entrypoint/internal/core"
)

func TestParseCredentialLine(t *testing.T) {
	tests := []struct {
		line     string
		domain   string
		username string
		password string
	}{
		{line: `user:pass`, username: "user", password: "pass"},
		{line: `DOMAIN\user:pass`, domain: "DOMAIN", username: "user", password: "pass"},
		{line: `DOMAIN/user:pass`, domain: "DOMAIN", username: "user", password: "pass"},
		{line: `user@corp.local:pass`, username: "user@corp.local", password: "pass"},
		{line: `user:`, username: "user", password: ""},
		{line: `:pass`, username: "", password: "pass"},
	}

	for _, tc := range tests {
		cred, err := ParseCredentialLine(tc.line)
		if err != nil {
			t.Fatalf("ParseCredentialLine(%q) returned error: %v", tc.line, err)
		}
		if cred.Domain != tc.domain || cred.Username != tc.username || cred.Password != tc.password {
			t.Fatalf("ParseCredentialLine(%q) = %+v", tc.line, cred)
		}
	}
}

func TestParseCredentialsIgnoresCommentsAndEmptyLines(t *testing.T) {
	raw := "\n# built-in defaults\nadmin:admin\n\nuser:user\n"

	creds, err := ParseCredentials(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseCredentials returned error: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
	if creds[0].Username != "admin" || creds[0].Password != "admin" {
		t.Fatalf("unexpected first credential: %+v", creds[0])
	}
	if creds[1].Username != "user" || creds[1].Password != "user" {
		t.Fatalf("unexpected second credential: %+v", creds[1])
	}
}

func TestMergeCredentialsDeduplicates(t *testing.T) {
	custom := []core.Credential{
		{Username: "admin", Password: "admin"},
		{Username: "user", Password: "user"},
	}
	top := []core.Credential{
		{Username: "admin", Password: "admin"},
		{Username: "test", Password: "test"},
	}

	merged := MergeCredentials(custom, top)
	if len(merged) != 3 {
		t.Fatalf("expected 3 merged credentials, got %d", len(merged))
	}
	if merged[0].Username != "admin" || merged[1].Username != "user" || merged[2].Username != "test" {
		t.Fatalf("unexpected merge order/content: %+v", merged)
	}
}
