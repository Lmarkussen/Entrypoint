package core

import (
	"context"
	"testing"
)

type fakeModule struct {
	name  string
	anon  bool
	creds bool
	ports []int
}

func (m fakeModule) Name() string                                                   { return m.name }
func (m fakeModule) Ports() []int                                                   { return m.ports }
func (m fakeModule) SupportsAnonymous() bool                                        { return m.anon }
func (m fakeModule) SupportsCredentials() bool                                      { return m.creds }
func (m fakeModule) Check(context.Context, Target, []Credential, Options) []Finding { return nil }

func TestSelectModulesAnonOnlySkipsTelnet(t *testing.T) {
	targets := []Target{
		{Host: "10.10.10.5", Port: 21, Service: "ftp"},
		{Host: "10.10.10.6", Port: 23, Service: "telnet"},
	}
	registry := map[string]Module{
		"ftp":    fakeModule{name: "ftp", anon: true, creds: true},
		"telnet": fakeModule{name: "telnet", anon: false, creds: true},
	}

	mods, skipped, err := SelectModules(targets, registry, nil, nil, Options{AnonOnly: true})
	if err != nil {
		t.Fatalf("SelectModules returned error: %v", err)
	}
	if len(mods) != 1 || mods[0].Name() != "ftp" {
		t.Fatalf("expected only ftp module, got %+v", mods)
	}
	if len(skipped) != 1 || skipped[0].Service != "telnet" {
		t.Fatalf("expected telnet skipped finding, got %+v", skipped)
	}
}

func TestSelectModulesSupportsLDAPAndLDAPSFilters(t *testing.T) {
	targets := []Target{
		{Host: "10.10.10.7", Port: 389, Service: "ldap"},
		{Host: "10.10.10.8", Port: 636, Service: "ldaps"},
	}
	registry := map[string]Module{
		"ldap":  fakeModule{name: "ldap", anon: true, creds: true},
		"ldaps": fakeModule{name: "ldaps", anon: true, creds: true},
	}

	mods, skipped, err := SelectModules(targets, registry, ParseNameSet("ldaps"), nil, Options{})
	if err != nil {
		t.Fatalf("SelectModules returned error: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("did not expect skipped targets, got %+v", skipped)
	}
	if len(mods) != 1 || mods[0].Name() != "ldaps" {
		t.Fatalf("expected only ldaps module, got %+v", mods)
	}
}

func TestSelectModulesSupportsSNMPFilter(t *testing.T) {
	targets := []Target{
		{Host: "10.10.10.9", Port: 161, Proto: "udp", Service: "snmp"},
	}
	registry := map[string]Module{
		"snmp": fakeModule{name: "snmp", anon: true, creds: false},
	}

	mods, skipped, err := SelectModules(targets, registry, ParseNameSet("snmp"), nil, Options{})
	if err != nil {
		t.Fatalf("SelectModules returned error: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("did not expect skipped targets, got %+v", skipped)
	}
	if len(mods) != 1 || mods[0].Name() != "snmp" {
		t.Fatalf("expected only snmp module, got %+v", mods)
	}
}

func TestSelectModulesSupportsWinRMFilter(t *testing.T) {
	targets := []Target{
		{Host: "10.10.10.10", Port: 5985, Proto: "tcp", Service: "winrm"},
		{Host: "10.10.10.11", Port: 5986, Proto: "tcp", Service: "winrm-ssl"},
	}
	registry := map[string]Module{
		"winrm":     fakeModule{name: "winrm", anon: false, creds: true},
		"winrm-ssl": fakeModule{name: "winrm-ssl", anon: false, creds: true},
	}

	mods, skipped, err := SelectModules(targets, registry, ParseNameSet("winrm"), nil, Options{})
	if err != nil {
		t.Fatalf("SelectModules returned error: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("did not expect skipped targets, got %+v", skipped)
	}
	if len(mods) != 1 || mods[0].Name() != "winrm" {
		t.Fatalf("expected only winrm module, got %+v", mods)
	}
}

func TestSelectModulesSupportsMSSQLFilter(t *testing.T) {
	targets := []Target{
		{Host: "10.10.10.12", Port: 1433, Proto: "tcp", Service: "mssql"},
	}
	registry := map[string]Module{
		"mssql": fakeModule{name: "mssql", anon: false, creds: true},
	}

	mods, skipped, err := SelectModules(targets, registry, ParseNameSet("mssql"), nil, Options{})
	if err != nil {
		t.Fatalf("SelectModules returned error: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("did not expect skipped targets, got %+v", skipped)
	}
	if len(mods) != 1 || mods[0].Name() != "mssql" {
		t.Fatalf("expected only mssql module, got %+v", mods)
	}
}
