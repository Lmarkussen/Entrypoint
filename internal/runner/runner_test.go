package runner

import (
	"context"
	"testing"
	"time"

	"entrypoint/internal/core"
)

type stubModule struct {
	name     string
	findings []core.Finding
}

func (m stubModule) Name() string              { return m.name }
func (m stubModule) Ports() []int              { return []int{0} }
func (m stubModule) SupportsAnonymous() bool   { return true }
func (m stubModule) SupportsCredentials() bool { return true }
func (m stubModule) Check(context.Context, core.Target, []core.Credential, core.Options) []core.Finding {
	return append([]core.Finding(nil), m.findings...)
}

func TestRunCollapsesRepeatedConnectionErrors(t *testing.T) {
	target := core.Target{Host: "10.10.10.10", Port: 389, Service: "ldap"}
	cfg := Config{
		Targets: []core.Target{target},
		Modules: []core.Module{
			stubModule{
				name: "ldap",
				findings: []core.Finding{
					core.ErrorFinding(target, "anonymous", "", "", "connect failed: dial tcp 10.10.10.10:389: socket: operation not permitted"),
					core.ErrorFinding(target, "credential", "lars", "", "connect failed: dial tcp 10.10.10.10:389: socket: operation not permitted"),
					core.ErrorFinding(target, "credential", "test", "", "connect failed: dial tcp 10.10.10.10:389: socket: operation not permitted"),
				},
			},
		},
		Options: core.Options{Threads: 1, Timeout: time.Second},
	}

	collected := make([]core.Finding, 0)
	cfg.OnFinding = func(f core.Finding) { collected = append(collected, f) }

	if err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("expected 1 collapsed finding, got %d: %+v", len(collected), collected)
	}
	if collected[0].AuthType != core.AuthTypeInfrastructure {
		t.Fatalf("expected infrastructure auth type, got %q", collected[0].AuthType)
	}
}

func TestRunDoesNotCollapseInvalidAuthFailures(t *testing.T) {
	target := core.Target{Host: "10.10.10.11", Port: 22, Service: "ssh"}
	cfg := Config{
		Targets: []core.Target{target},
		Modules: []core.Module{
			stubModule{
				name: "ssh",
				findings: []core.Finding{
					core.InvalidFinding(target, "credential", "lars", "", "login failed"),
					core.InvalidFinding(target, "credential", "test", "", "login failed"),
				},
			},
		},
		Options: core.Options{Threads: 1, Timeout: time.Second},
	}

	collected := make([]core.Finding, 0)
	cfg.OnFinding = func(f core.Finding) { collected = append(collected, f) }

	if err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("expected invalid findings not collapsed, got %d: %+v", len(collected), collected)
	}
}

func TestRunSummarizesRepeatedInvalidFailuresForSameUsername(t *testing.T) {
	target := core.Target{Host: "10.10.10.12", Port: 22, Service: "ssh"}
	cfg := Config{
		Targets: []core.Target{target},
		Modules: []core.Module{
			stubModule{
				name: "ssh",
				findings: []core.Finding{
					core.InvalidFinding(target, "credential", "admin", "", "login failed"),
					core.InvalidFinding(target, "credential", "admin", "", "authentication failed"),
					core.InvalidFinding(target, "credential", "admin", "", "invalid credentials"),
				},
			},
		},
		Options: core.Options{Threads: 1, Timeout: time.Second},
	}

	collected := make([]core.Finding, 0)
	cfg.OnFinding = func(f core.Finding) { collected = append(collected, f) }

	if err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("expected 1 summarized invalid finding, got %d: %+v", len(collected), collected)
	}
	if collected[0].Notes != "login failed; tried 3 passwords" {
		t.Fatalf("unexpected summarized note: %q", collected[0].Notes)
	}
	if collected[0].Password != "" {
		t.Fatalf("unexpected password leakage: %+v", collected[0])
	}
}
