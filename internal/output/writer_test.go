package output

import (
	"os"
	"path/filepath"
	"testing"

	"entrypoint/internal/core"
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

	manager, err := NewManager(fullPath, successPath)
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
	if err := manager.WriteSuccessFinding(core.ValidFinding(core.Target{Host: "10.10.10.2", Port: 445, Service: "smb"}, "credential", `CORP\test`, "shares=SYSVOL,NETLOGON", "")); err != nil {
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
	if got != "VALID [C] smb 10.10.10.2:445 user=CORP\\test; shares=SYSVOL,NETLOGON\n" {
		t.Fatalf("unexpected success log contents: %q", got)
	}
	if containsANSI(got) {
		t.Fatalf("success log should not contain ANSI escapes: %q", got)
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
