package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"entrypoint/internal/core"
	"entrypoint/internal/output"
)

func TestShouldWriteToStdoutWithValidOnly(t *testing.T) {
	valid := core.ValidFinding(core.Target{Host: "10.10.10.1", Port: 22, Service: "ssh"}, "credential", "test", "whoami => test", "")
	invalid := core.InvalidFinding(core.Target{Host: "10.10.10.1", Port: 22, Service: "ssh"}, "credential", "admin", "", "login failed")
	errFinding := core.ErrorFinding(core.Target{Host: "10.10.10.1", Port: 22, Service: "ssh"}, core.AuthTypeInfrastructure, "", "", "timeout")
	skipped := core.SkippedFinding(core.Target{Host: "10.10.10.1", Port: 22, Service: "ssh"}, "credential", "no credentials supplied")

	if shouldWriteToStdout(true, outputLinePreamble, nil) {
		t.Fatal("did not expect preamble on stdout in valid-only mode")
	}
	if !shouldWriteToStdout(true, outputLineAlways, nil) {
		t.Fatal("expected totals/summary block on stdout in valid-only mode")
	}
	if !shouldWriteToStdout(true, outputLineFinding, &valid) {
		t.Fatal("expected valid finding on stdout in valid-only mode")
	}
	for _, finding := range []*core.Finding{&invalid, &errFinding, &skipped} {
		if shouldWriteToStdout(true, outputLineFinding, finding) {
			t.Fatalf("did not expect non-valid finding on stdout in valid-only mode: %+v", *finding)
		}
	}
}

func TestShouldWriteToStdoutWithoutValidOnly(t *testing.T) {
	invalid := core.InvalidFinding(core.Target{Host: "10.10.10.1", Port: 22, Service: "ssh"}, "credential", "admin", "", "login failed")

	if !shouldWriteToStdout(false, outputLinePreamble, nil) {
		t.Fatal("expected preamble on stdout without valid-only")
	}
	if !shouldWriteToStdout(false, outputLineFinding, &invalid) {
		t.Fatal("expected finding on stdout without valid-only")
	}
	if !shouldWriteToStdout(false, outputLineAlways, nil) {
		t.Fatal("expected always lines on stdout without valid-only")
	}
}

func TestWriteOutputLineSkipsStdoutButWritesFullOutfile(t *testing.T) {
	dir := t.TempDir()
	fullPath := filepath.Join(dir, "entrypoint.log")
	successPath := filepath.Join(dir, "valid.log")

	manager, err := output.NewManager(fullPath, successPath, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	var stdout bytes.Buffer
	if err := writeOutputLine(&stdout, manager, "COLOR\n", "PLAIN\n", false); err != nil {
		t.Fatalf("writeOutputLine returned error: %v", err)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(data) != "PLAIN\n" {
		t.Fatalf("unexpected outfile contents: %q", string(data))
	}
}

func TestWriteOutputLineWritesStdoutAndOutfile(t *testing.T) {
	dir := t.TempDir()
	fullPath := filepath.Join(dir, "entrypoint.log")

	manager, err := output.NewManager(fullPath, "", false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	defer manager.Close()

	var stdout bytes.Buffer
	if err := writeOutputLine(&stdout, manager, "COLOR\n", "PLAIN\n", true); err != nil {
		t.Fatalf("writeOutputLine returned error: %v", err)
	}

	if stdout.String() != "COLOR\n" {
		t.Fatalf("unexpected stdout contents: %q", stdout.String())
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(data) != "PLAIN\n" {
		t.Fatalf("unexpected outfile contents: %q", string(data))
	}
}
