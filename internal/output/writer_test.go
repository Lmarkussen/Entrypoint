package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"entrypoint/internal/core"
	"entrypoint/internal/ui"
)

func TestWriteLineWritesPlainText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entrypoint.log")
	writer, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	defer writer.Close()

	if err := writer.WriteLine("plain line\n"); err != nil {
		t.Fatalf("WriteLine returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(data) != "plain line\n" {
		t.Fatalf("unexpected file contents: %q", string(data))
	}
}

func TestNewWriterDoesNotCreateParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "entrypoint.log")
	_, err := NewWriter(path)
	if err == nil {
		t.Fatal("expected error when parent directory does not exist")
	}
}

func TestManagerWritesOnlyValidFindingsToSuccessLog(t *testing.T) {
	dir := t.TempDir()
	fullPath := filepath.Join(dir, "entrypoint.log")
	successPath := filepath.Join(dir, "valid.log")

	manager, err := NewManager(fullPath, successPath, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	if err := manager.WriteFull("[*] header\n"); err != nil {
		t.Fatalf("WriteFull returned error: %v", err)
	}
	if err := manager.WriteSuccessFinding(core.InvalidFinding(core.Target{Host: "10.10.10.1", Port: 21, Service: "ftp"}, "credential", "admin", "", "login failed")); err != nil {
		t.Fatalf("WriteSuccessFinding invalid returned error: %v", err)
	}
	if err := manager.WriteSuccessFinding(core.WithCredentialPassword(core.ValidFinding(core.Target{Host: "10.10.10.2", Port: 445, Service: "smb"}, "credential", `CORP\test`, "shares=SYSVOL,NETLOGON", ""), "Winter2024!")); err != nil {
		t.Fatalf("WriteSuccessFinding valid returned error: %v", err)
	}

	fullData, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("ReadFile full returned error: %v", err)
	}
	if string(fullData) != "[*] header\n" {
		t.Fatalf("unexpected full file contents: %q", string(fullData))
	}

	successData, err := os.ReadFile(successPath)
	if err != nil {
		t.Fatalf("ReadFile success returned error: %v", err)
	}
	got := string(successData)
	if got != "VALID [C] smb 10.10.10.2:445 user=CORP\\test; password=Winter2024!; shares=SYSVOL,NETLOGON\n" {
		t.Fatalf("unexpected success log contents: %q", got)
	}
	if containsANSI(got) {
		t.Fatalf("success log should not contain ANSI escapes: %q", got)
	}
}

func TestManagerWritesRedisValidFindingOnlyToSuccessLog(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewManager(filepath.Join(dir, "entrypoint.log"), filepath.Join(dir, "valid.log"), false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	if err := manager.WriteSuccessFinding(core.ValidFinding(
		core.Target{Host: "10.10.10.30", Port: 6379, Service: "redis"},
		"anonymous",
		"",
		"redis_version=7.0.15; role=master",
		"no-auth",
	)); err != nil {
		t.Fatalf("WriteSuccessFinding returned error: %v", err)
	}
	if err := manager.WriteSuccessFinding(core.InvalidFinding(
		core.Target{Host: "10.10.10.31", Port: 6379, Service: "redis"},
		"anonymous",
		"",
		"",
		"no-auth denied",
	)); err != nil {
		t.Fatalf("WriteSuccessFinding returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "valid.log"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	got := string(data)
	if got != "VALID [A] redis 10.10.10.30:6379 no-auth; redis_version=7.0.15; role=master\n" {
		t.Fatalf("unexpected success log contents: %q", got)
	}
}

func TestManagerWritesNFSValidFindingOnlyToSuccessLog(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewManager(filepath.Join(dir, "entrypoint.log"), filepath.Join(dir, "valid.log"), false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	if err := manager.WriteSuccessFinding(core.ValidFinding(
		core.Target{Host: "10.10.10.40", Port: 2049, Service: "nfs"},
		"anonymous",
		"",
		"exports=/srv/share,/backup",
		"access appears world-readable",
	)); err != nil {
		t.Fatalf("WriteSuccessFinding returned error: %v", err)
	}
	if err := manager.WriteSuccessFinding(core.ErrorFinding(
		core.Target{Host: "10.10.10.41", Port: 2049, Service: "nfs"},
		"anonymous",
		"",
		"",
		"timeout/no response",
	)); err != nil {
		t.Fatalf("WriteSuccessFinding returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "valid.log"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	got := string(data)
	if got != "VALID [A] nfs 10.10.10.40:2049 access appears world-readable; exports=/srv/share,/backup\n" {
		t.Fatalf("unexpected success log contents: %q", got)
	}
	if containsANSI(got) {
		t.Fatalf("success log should not contain ANSI escapes: %q", got)
	}
}

func TestManagerWritesRsyncValidFindingOnlyToSuccessLog(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewManager(filepath.Join(dir, "entrypoint.log"), filepath.Join(dir, "valid.log"), false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	if err := manager.WriteSuccessFinding(core.ValidFinding(
		core.Target{Host: "10.10.10.50", Port: 873, Service: "rsync"},
		"anonymous",
		"",
		"modules=backup,home,www",
		"",
	)); err != nil {
		t.Fatalf("WriteSuccessFinding returned error: %v", err)
	}
	if err := manager.WriteSuccessFinding(core.InvalidFinding(
		core.Target{Host: "10.10.10.51", Port: 873, Service: "rsync"},
		"anonymous",
		"",
		"",
		"no modules visible",
	)); err != nil {
		t.Fatalf("WriteSuccessFinding returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "valid.log"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	got := string(data)
	if got != "VALID [A] rsync 10.10.10.50:873 modules=backup,home,www\n" {
		t.Fatalf("unexpected success log contents: %q", got)
	}
	if containsANSI(got) {
		t.Fatalf("success log should not contain ANSI escapes: %q", got)
	}
}

func TestManagerRedactsSuccessfulPasswordsInSuccessLogWhenRequested(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewManager(filepath.Join(dir, "entrypoint.log"), filepath.Join(dir, "valid.log"), true)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	if err := manager.WriteSuccessFinding(core.WithCredentialPassword(
		core.ValidFinding(core.Target{Host: "10.10.10.70", Port: 22, Service: "ssh"}, "credential", "test", "whoami => test", ""),
		"SuperSecret123!",
	)); err != nil {
		t.Fatalf("WriteSuccessFinding returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "valid.log"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	got := string(data)
	if strings.Contains(got, "password=") {
		t.Fatalf("did not expect password in redacted success log: %q", got)
	}
	if !strings.Contains(got, "user=test; whoami => test") {
		t.Fatalf("unexpected redacted success log contents: %q", got)
	}
}

func TestManagerWritesPriorityBlockPlainTextToOutfile(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewManager(filepath.Join(dir, "entrypoint.log"), "", false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	block := ui.PriorityTargetsBlock([]core.Finding{
		core.ValidFinding(
			core.Target{Host: "10.10.10.60", Port: 22, Service: "ssh"},
			"credential",
			"test",
			"whoami => test",
			"",
		),
	}, false, false)

	if err := manager.WriteFull(block); err != nil {
		t.Fatalf("WriteFull returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "entrypoint.log"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	got := string(data)
	if containsANSI(got) {
		t.Fatalf("outfile should not contain ANSI escapes: %q", got)
	}
	if !strings.Contains(got, "==== PRIORITY TARGETS ====") {
		t.Fatalf("missing priority block in outfile: %q", got)
	}
}

func TestManagerWritesCollapsedInfrastructureErrorPlainTextToOutfile(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewManager(filepath.Join(dir, "entrypoint.log"), "", false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	line := ui.FindingLine(core.ErrorFinding(
		core.Target{Host: "10.10.10.80", Port: 389, Service: "ldap"},
		core.AuthTypeInfrastructure,
		"",
		"",
		"local socket blocked / operation not permitted",
	), false, false)

	if err := manager.WriteFull(line); err != nil {
		t.Fatalf("WriteFull returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "entrypoint.log"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	got := string(data)
	if containsANSI(got) {
		t.Fatalf("outfile should not contain ANSI escapes: %q", got)
	}
	if !strings.Contains(got, "[I] ldap") {
		t.Fatalf("expected infrastructure auth label in outfile: %q", got)
	}
}

func containsANSI(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			return true
		}
	}
	return false
}
