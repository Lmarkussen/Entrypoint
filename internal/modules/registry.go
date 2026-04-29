package modules

import "entrypoint/internal/core"

func DefaultRegistry() map[string]core.Module {
	mods := []core.Module{
		NewFTPModule(),
		NewLDAPModule(),
		NewLDAPSModule(),
		NewMSSQLModule(),
		NewSNMPModule(),
		NewWinRMModule(),
		NewWinRMSSLModule(),
		NewSSHModule(),
		NewSMBModule(),
		NewTelnetModule(),
	}

	registry := make(map[string]core.Module, len(mods))
	for _, mod := range mods {
		registry[mod.Name()] = mod
	}
	return registry
}
