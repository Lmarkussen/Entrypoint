package core

import (
	"context"
	"time"
)

type Module interface {
	Name() string
	Ports() []int
	SupportsAnonymous() bool
	SupportsCredentials() bool
	Check(ctx context.Context, target Target, creds []Credential, opts Options) []Finding
}

type Target struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
}

type Credential struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Finding struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	AuthType string `json:"auth_type"`
	Username string `json:"username"`
	Success  bool   `json:"success"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
	Notes    string `json:"notes"`
}

type Options struct {
	Timeout                time.Duration `json:"timeout"`
	Threads                int           `json:"threads"`
	AnonOnly               bool          `json:"anon_only"`
	IncludeAnon            bool          `json:"include_anon"`
	StopOnValid            bool          `json:"stop_on_valid"`
	SafeMode               bool          `json:"safe_mode"`
	LDAPInsecureSkipVerify bool          `json:"ldap_insecure_skip_verify"`
	SNMPCommunities        []string      `json:"snmp_communities"`
	WinRMInsecure          bool          `json:"winrm_insecure"`
}

type Summary struct {
	TotalTargets     int
	ByService        map[string]int
	SelectedServices []string
}

type FindingStats struct {
	Valid     int
	Invalid   int
	Errors    int
	Skipped   int
	Anonymous int
}

func DefaultOptions() Options {
	return Options{
		Timeout:     5 * time.Second,
		Threads:     50,
		AnonOnly:    false,
		IncludeAnon: true,
		StopOnValid: true,
		SafeMode:    true,
	}
}
