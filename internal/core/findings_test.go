package core

import "testing"

func TestClassifyFinding(t *testing.T) {
	target := Target{Host: "10.10.10.5", Port: 21, Service: "ftp"}
	valid := ValidFinding(target, "anonymous", "anonymous", "pwd=/", "")
	invalid := InvalidFinding(target, "credential", "user", "", "530 Login incorrect")
	errFinding := ErrorFinding(target, "credential", "user", "", "timeout")
	skipped := SkippedFinding(target, "mode", "anon-only")

	if got := ClassifyFinding(valid); got != "valid" {
		t.Fatalf("valid classified as %q", got)
	}
	if got := ClassifyFinding(invalid); got != "invalid" {
		t.Fatalf("invalid classified as %q", got)
	}
	if got := ClassifyFinding(errFinding); got != "error" {
		t.Fatalf("error classified as %q", got)
	}
	if got := ClassifyFinding(skipped); got != "skipped" {
		t.Fatalf("skipped classified as %q", got)
	}
}
