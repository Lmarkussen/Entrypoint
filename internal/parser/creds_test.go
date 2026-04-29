package parser

import "testing"

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
