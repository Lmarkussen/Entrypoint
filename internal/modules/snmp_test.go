package modules

import (
	"context"
	"strings"
	"testing"
	"time"

	"entrypoint/internal/core"
)

func TestSNMPCommunitiesDefaults(t *testing.T) {
	got := snmpCommunities(core.Options{})
	want := []string{"public", "private", "monitor", "read", "readonly"}

	if len(got) != len(want) {
		t.Fatalf("unexpected community count: got %d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected communities: got %v want %v", got, want)
		}
	}
}

func TestSNMPCommunitiesCustomDeduped(t *testing.T) {
	got := snmpCommunities(core.Options{SNMPCommunities: []string{" public ", "monitor", "public", "", "readonly"}})
	want := []string{"public", "monitor", "readonly"}

	if len(got) != len(want) {
		t.Fatalf("unexpected community count: got %d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected communities: got %v want %v", got, want)
		}
	}
}

func TestSNMPCheckReturnsValidFindingForWorkingCommunity(t *testing.T) {
	original := snmpAttemptFunc
	t.Cleanup(func() { snmpAttemptFunc = original })

	snmpAttemptFunc = func(_ context.Context, _ core.Target, community string, _ time.Duration) snmpAttemptResult {
		if community == "public" {
			return snmpAttemptResult{
				community:  community,
				valid:      true,
				foundProof: true,
				notes:      "community=public",
				evidence:   "sysName=core-sw01; sysDescr=Cisco IOS Software...",
			}
		}
		return snmpAttemptResult{community: community, noResponse: true}
	}

	mod := NewSNMPModule()
	target := core.Target{Host: "10.10.10.20", Port: 161, Proto: "udp", Service: "snmp"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, StopOnValid: true, Timeout: time.Second})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "valid" {
		t.Fatalf("expected valid finding, got %q", got)
	}
	if findings[0].Username != "public" {
		t.Fatalf("expected working community in username field, got %q", findings[0].Username)
	}
	if !strings.Contains(findings[0].Notes, "community=public") {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}

func TestSNMPCheckRedactsFailedCustomCommunities(t *testing.T) {
	original := snmpAttemptFunc
	t.Cleanup(func() { snmpAttemptFunc = original })

	snmpAttemptFunc = func(_ context.Context, _ core.Target, community string, _ time.Duration) snmpAttemptResult {
		return snmpAttemptResult{community: community, noResponse: false, foundProof: true}
	}

	mod := NewSNMPModule()
	target := core.Target{Host: "10.10.10.21", Port: 161, Proto: "udp", Service: "snmp"}
	findings := mod.Check(context.Background(), target, nil, core.Options{
		IncludeAnon:     true,
		StopOnValid:     true,
		Timeout:         time.Second,
		SNMPCommunities: []string{"custom-ro", "custom-monitor"},
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 summarized finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "invalid" {
		t.Fatalf("expected invalid finding, got %q", got)
	}
	if findings[0].Notes != "no valid community strings; tried 2" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
	if strings.Contains(findings[0].Notes, "custom-ro") || strings.Contains(findings[0].Notes, "custom-monitor") {
		t.Fatalf("failed community strings leaked in notes: %q", findings[0].Notes)
	}
	if strings.Contains(findings[0].Evidence, "custom-ro") || strings.Contains(findings[0].Evidence, "custom-monitor") {
		t.Fatalf("failed community strings leaked in evidence: %q", findings[0].Evidence)
	}
}

func TestSNMPCheckReturnsErrorOnNoResponses(t *testing.T) {
	original := snmpAttemptFunc
	t.Cleanup(func() { snmpAttemptFunc = original })

	snmpAttemptFunc = func(_ context.Context, _ core.Target, community string, _ time.Duration) snmpAttemptResult {
		return snmpAttemptResult{community: community, noResponse: true}
	}

	mod := NewSNMPModule()
	target := core.Target{Host: "10.10.10.22", Port: 161, Proto: "udp", Service: "snmp"}
	findings := mod.Check(context.Background(), target, nil, core.Options{IncludeAnon: true, StopOnValid: true, Timeout: time.Second})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := core.ClassifyFinding(findings[0]); got != "error" {
		t.Fatalf("expected error finding, got %q", got)
	}
	if findings[0].Notes != "timeout/no response" {
		t.Fatalf("unexpected note: %q", findings[0].Notes)
	}
}
