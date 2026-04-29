package ui

import (
	"bytes"
	"strings"
	"testing"

	"entrypoint/internal/core"
)

func TestPrintFindingShowsCredentialAuthLabelAndUsername(t *testing.T) {
	var buf bytes.Buffer
	finding := core.InvalidFinding(
		core.Target{Host: "10.150.64.67", Port: 21, Service: "ftp"},
		"credential",
		"admin",
		"banner=220 (vsFTPd 3.0.5)",
		"login failed",
	)

	PrintFinding(&buf, finding)
	out := buf.String()

	if !strings.Contains(out, "[C]") {
		t.Fatalf("expected credential auth label in %q", out)
	}
	if !strings.Contains(out, "user=admin; login failed; banner=220 (vsFTPd 3.0.5)") {
		t.Fatalf("unexpected terminal detail: %q", out)
	}
}

func TestPrintFindingShowsAnonymousAuthLabel(t *testing.T) {
	var buf bytes.Buffer
	finding := core.InvalidFinding(
		core.Target{Host: "10.150.64.67", Port: 21, Service: "ftp"},
		"anonymous",
		"anonymous",
		"",
		"anonymous denied; tried anonymous:anonymous, anonymous:<blank>",
	)

	PrintFinding(&buf, finding)
	out := buf.String()

	if !strings.Contains(out, "[A]") {
		t.Fatalf("expected anonymous auth label in %q", out)
	}
	if strings.Contains(out, "user=") {
		t.Fatalf("did not expect user prefix in anonymous output: %q", out)
	}
}

func TestFindingLinePlainTextHasNoANSI(t *testing.T) {
	finding := core.InvalidFinding(
		core.Target{Host: "10.150.64.67", Port: 21, Service: "ftp"},
		"credential",
		"admin",
		"banner=220 (vsFTPd 3.0.5)",
		"login failed",
	)

	line := FindingLine(finding, false)
	if strings.Contains(line, "\033[") {
		t.Fatalf("unexpected ANSI codes in plain line: %q", line)
	}
	if !strings.Contains(line, "[C]") {
		t.Fatalf("expected auth label in plain line: %q", line)
	}
}

func TestSuccessLogLineIsPlainAndOnlyContainsUsefulDetail(t *testing.T) {
	finding := core.ValidFinding(
		core.Target{Host: "10.10.10.20", Port: 161, Service: "snmp"},
		"anonymous",
		"public",
		"sysName=core-sw01",
		"community=public",
	)

	line := SuccessLogLine(finding)
	if containsANSI(line) {
		t.Fatalf("unexpected ANSI codes in success log line: %q", line)
	}
	if !strings.Contains(line, "VALID [A] snmp 10.10.10.20:161 community=public; sysName=core-sw01") {
		t.Fatalf("unexpected success log line: %q", line)
	}
}

func TestBannerTextPlainHasNoANSI(t *testing.T) {
	text := "ENTRYPOINT\n"
	if got := BannerText(text, false); got != text {
		t.Fatalf("expected plain banner text, got %q", got)
	}
	if strings.Contains(BannerText(text, false), "\033[") {
		t.Fatal("plain banner unexpectedly contains ANSI escapes")
	}
}

func TestRunSummaryBlockGroupsValidByHost(t *testing.T) {
	findings := []core.Finding{
		core.ValidFinding(core.Target{Host: "172.16.0.30", Port: 21, Service: "ftp"}, "credential", "test", "", ""),
		core.ValidFinding(core.Target{Host: "172.16.0.30", Port: 22, Service: "ssh"}, "credential", "test", "", ""),
		core.ValidFinding(core.Target{Host: "172.16.0.30", Port: 445, Service: "smb"}, "credential", "test", "", ""),
		core.InvalidFinding(core.Target{Host: "172.16.0.31", Port: 21, Service: "ftp"}, "credential", "admin", "", "login failed"),
		core.SkippedFinding(core.Target{Host: "172.16.0.30", Port: 139, Service: "smb"}, "null-session", "not supported"),
	}

	out := RunSummaryBlock(findings, false)
	if !strings.Contains(out, "==== SUMMARY ====") {
		t.Fatalf("missing summary header: %q", out)
	}
	if !strings.Contains(out, "172.16.0.30:\n  ftp     [C] test\n  smb     [C] test\n  ssh     [C] test\n") {
		t.Fatalf("unexpected valid host grouping: %q", out)
	}
	if !strings.Contains(out, "ftp     valid=1 invalid=1 errors=0 skipped=0") {
		t.Fatalf("missing ftp counts: %q", out)
	}
	if !strings.Contains(out, "smb     valid=1 invalid=0 errors=0 skipped=1") {
		t.Fatalf("missing smb counts: %q", out)
	}
}

func TestRunSummaryBlockPlainTextHasNoANSI(t *testing.T) {
	findings := []core.Finding{
		core.ValidFinding(core.Target{Host: "172.16.0.30", Port: 389, Service: "ldap"}, "anonymous", "", "defaultNamingContext=DC=corp,DC=local", "anonymous bind + RootDSE query successful"),
	}

	out := RunSummaryBlock(findings, false)
	if strings.Contains(out, "\033[") {
		t.Fatalf("plain summary unexpectedly contains ANSI escapes: %q", out)
	}
	if !strings.Contains(out, "ldap    [A] anonymous") {
		t.Fatalf("expected anonymous summary principal, got %q", out)
	}
}

func TestRunSummaryBlockIncludesSNMPCounts(t *testing.T) {
	findings := []core.Finding{
		core.ValidFinding(core.Target{Host: "172.16.0.40", Port: 161, Service: "snmp"}, "anonymous", "public", "sysName=core-sw01", "community=public"),
		core.InvalidFinding(core.Target{Host: "172.16.0.41", Port: 161, Service: "snmp"}, "anonymous", "", "", "no valid community strings; tried 5"),
	}

	out := RunSummaryBlock(findings, false)
	if !strings.Contains(out, "snmp    valid=1 invalid=1 errors=0 skipped=0") {
		t.Fatalf("missing snmp counts: %q", out)
	}
	if !strings.Contains(out, "snmp    [A] public") {
		t.Fatalf("missing snmp valid summary principal: %q", out)
	}
}

func TestPriorityTargetsBlockGroupsAndSorts(t *testing.T) {
	findings := []core.Finding{
		core.ValidFinding(core.Target{Host: "10.10.1.30", Port: 445, Service: "smb"}, "credential", "test", "shares=IPC$,backup", ""),
		core.ValidFinding(core.Target{Host: "10.10.1.20", Port: 5985, Service: "winrm"}, "credential", `CORP\svc-backup`, `whoami => corp\svc-backup`, ""),
		core.ValidFinding(core.Target{Host: "10.10.1.50", Port: 161, Service: "snmp"}, "anonymous", "public", "sysName=core-sw01", "community=public"),
		core.ValidFinding(core.Target{Host: "10.10.1.21", Port: 22, Service: "ssh"}, "credential", "test", "whoami => test", "ssh access confirmed"),
		core.ValidFinding(core.Target{Host: "10.10.1.40", Port: 6379, Service: "redis"}, "anonymous", "", "role=master", "no-auth"),
	}

	out := PriorityTargetsBlock(findings, false)
	if !strings.Contains(out, "==== PRIORITY TARGETS ====") {
		t.Fatalf("missing priority header: %q", out)
	}

	high := strings.Index(out, "10.10.1.20:5985")
	highNext := strings.Index(out, "10.10.1.21:22")
	if high == -1 || highNext == -1 || high > highNext {
		t.Fatalf("expected HIGH entries sorted by host: %q", out)
	}
	if !strings.Contains(out, "HIGH:\n  10.10.1.20:5985") {
		t.Fatalf("missing HIGH section: %q", out)
	}
	if !strings.Contains(out, "MEDIUM:\n  10.10.1.30:445") {
		t.Fatalf("missing MEDIUM section: %q", out)
	}
	if !strings.Contains(out, "LOW:\n  10.10.1.50:161") {
		t.Fatalf("missing LOW section: %q", out)
	}
	if !strings.Contains(out, "[A] no-auth") {
		t.Fatalf("missing redis anonymous identity: %q", out)
	}
	if !strings.Contains(out, "[A] public") {
		t.Fatalf("missing snmp community identity: %q", out)
	}
}

func TestPriorityTargetsBlockNoneWhenNoValidFindings(t *testing.T) {
	findings := []core.Finding{
		core.InvalidFinding(core.Target{Host: "10.10.1.21", Port: 21, Service: "ftp"}, "anonymous", "", "", "anonymous denied"),
	}

	out := PriorityTargetsBlock(findings, false)
	if out != "==== PRIORITY TARGETS ====\nnone\n" {
		t.Fatalf("unexpected no-valid block: %q", out)
	}
}

func TestPriorityTargetsBlockTruncatesEvidenceAndRedactsPasswords(t *testing.T) {
	longEvidence := strings.Repeat("A", 140) + " password=Secret123!"
	findings := []core.Finding{
		core.ValidFinding(core.Target{Host: "10.10.1.20", Port: 5985, Service: "winrm"}, "credential", "admin", longEvidence, ""),
	}

	out := PriorityTargetsBlock(findings, false)
	if strings.Contains(out, "Secret123!") {
		t.Fatalf("priority block leaked password: %q", out)
	}
	if !strings.Contains(out, "password=<redacted>") && !strings.Contains(out, "...") {
		t.Fatalf("expected redaction or truncation marker in %q", out)
	}
	if len(strings.Split(out, "\n")[2]) > 200 {
		t.Fatalf("priority line too long after truncation: %q", out)
	}
}

func TestPriorityTargetsBlockPlainTextHasNoANSI(t *testing.T) {
	findings := []core.Finding{
		core.ValidFinding(core.Target{Host: "10.10.1.20", Port: 873, Service: "rsync"}, "anonymous", "", "modules=backup,www", ""),
	}

	out := PriorityTargetsBlock(findings, false)
	if strings.Contains(out, "\033[") {
		t.Fatalf("plain priority block unexpectedly contains ANSI escapes: %q", out)
	}
	if !strings.Contains(out, "[A] anonymous") {
		t.Fatalf("expected anonymous rsync identity, got %q", out)
	}
}

func TestPriorityTargetsBlockHandlesNullSessionIdentity(t *testing.T) {
	findings := []core.Finding{
		core.ValidFinding(core.Target{Host: "10.10.1.30", Port: 445, Service: "smb"}, "null-session", "", "shares=IPC$,backup", ""),
	}

	out := PriorityTargetsBlock(findings, false)
	if !strings.Contains(out, "[A] null/guest") {
		t.Fatalf("expected null/guest identity, got %q", out)
	}
}

func containsANSI(s string) bool {
	return strings.Contains(s, "\033[")
}
