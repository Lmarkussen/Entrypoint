package modules

import "testing"

func TestFormatTelnetProofEvidenceWhoamiStripsMOTD(t *testing.T) {
	raw := `whoami
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0 x86_64)
 * Documentation:  https://help.ubuntu.com
 * System information as of Tue Apr 29 10:00:00 UTC 2026
Last login: Tue Apr 29 09:59:50 2026 from 10.10.10.1
test
test@host:~$`

	got := formatTelnetProofEvidence(raw, "whoami")
	if got != "test" {
		t.Fatalf("expected concise whoami result, got %q", got)
	}
}

func TestFormatTelnetProofEvidenceIDKeepsActualCommandResult(t *testing.T) {
	raw := `id
Welcome to Ubuntu
uid=1000(test) gid=1000(test) groups=1000(test),27(sudo)
test@host:~$`

	got := formatTelnetProofEvidence(raw, "id")
	want := "uid=1000(test) gid=1000(test) groups=1000(test),27(sudo)"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatTelnetProofEvidenceHostnameUsesFinalResultLine(t *testing.T) {
	raw := `hostname
Linux host 5.15.0-100-generic x86_64
target-host
user@target-host:~$`

	got := formatTelnetProofEvidence(raw, "hostname")
	if got != "target-host" {
		t.Fatalf("expected hostname result, got %q", got)
	}
}
