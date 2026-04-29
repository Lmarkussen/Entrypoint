package modules

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

func TestCheckTelnetAttemptConnectionClosedBeforeLoginPrompt(t *testing.T) {
	origDial := telnetDialContext
	origReadUntil := telnetReadUntilFunc
	origProof := telnetProofSessionFunc
	origWrite := telnetWriteLineFunc
	t.Cleanup(func() {
		telnetDialContext = origDial
		telnetReadUntilFunc = origReadUntil
		telnetProofSessionFunc = origProof
		telnetWriteLineFunc = origWrite
	})

	telnetDialContext = func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_ = server.Close()
		}()
		return client, nil
	}
	telnetReadUntilFunc = telnetReadUntil
	telnetProofSessionFunc = telnetProofSession
	telnetWriteLineFunc = telnetWriteLine

	target := core.Target{Host: "10.10.10.30", Port: 23, Service: "telnet"}
	cred := core.Credential{Username: "admin", Password: "badpass"}
	finding := checkTelnetAttempt(context.Background(), target, cred, 250*time.Millisecond)

	if got := core.ClassifyFinding(finding); got != "error" {
		t.Fatalf("expected error classification, got %q", got)
	}
	if finding.Notes != "connection closed before login prompt" {
		t.Fatalf("unexpected note: %q", finding.Notes)
	}
	if strings.Contains(finding.Notes, "badpass") || strings.Contains(finding.Evidence, "badpass") {
		t.Fatalf("password leaked in finding: %+v", finding)
	}
}

func TestCheckTelnetAttemptRepeatedLoginPromptIsInvalid(t *testing.T) {
	origDial := telnetDialContext
	origReadUntil := telnetReadUntilFunc
	origProof := telnetProofSessionFunc
	origWrite := telnetWriteLineFunc
	t.Cleanup(func() {
		telnetDialContext = origDial
		telnetReadUntilFunc = origReadUntil
		telnetProofSessionFunc = origProof
		telnetWriteLineFunc = origWrite
	})

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	telnetDialContext = func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
		return client, nil
	}

	call := 0
	telnetReadUntilFunc = func(_ context.Context, _ net.Conn, _ time.Duration, _ func(string) bool) (string, error) {
		call++
		switch call {
		case 1:
			return "login:", nil
		case 2:
			return "Password:", nil
		case 3:
			return "login:", nil
		default:
			return "", io.EOF
		}
	}
	telnetProofSessionFunc = func(context.Context, net.Conn, time.Duration) (string, error) {
		return "", io.EOF
	}
	telnetWriteLineFunc = func(net.Conn, string) error { return nil }

	target := core.Target{Host: "10.10.10.31", Port: 23, Service: "telnet"}
	cred := core.Credential{Username: "admin", Password: "badpass"}
	finding := checkTelnetAttempt(context.Background(), target, cred, time.Second)

	if got := core.ClassifyFinding(finding); got != "invalid" {
		t.Fatalf("expected invalid classification, got %q", got)
	}
	if !strings.Contains(finding.Notes, "login:") {
		t.Fatalf("expected repeated login prompt in note, got %q", finding.Notes)
	}
}
