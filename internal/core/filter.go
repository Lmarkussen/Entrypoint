package core

import (
	"fmt"
	"sort"
	"strings"
)

func ParseNameSet(raw string) map[string]struct{} {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	out := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

func BuildSummary(targets []Target, modules []Module) Summary {
	byService := make(map[string]int)
	for _, target := range targets {
		if target.Service == "" {
			continue
		}
		byService[target.Service]++
	}

	selected := make([]string, 0, len(modules))
	for _, mod := range modules {
		selected = append(selected, mod.Name())
	}
	sort.Strings(selected)

	return Summary{
		TotalTargets:     len(targets),
		ByService:        byService,
		SelectedServices: selected,
	}
}

func SelectModules(targets []Target, registry map[string]Module, only, skip map[string]struct{}, opts Options) ([]Module, []Finding, error) {
	discovered := make(map[string]struct{})
	skippedTargets := make([]Finding, 0)
	for _, target := range targets {
		if target.Service != "" {
			discovered[target.Service] = struct{}{}
		}
	}

	if len(only) > 0 {
		for name := range only {
			if _, ok := registry[name]; !ok {
				return nil, nil, fmt.Errorf("unsupported module in --only: %s", name)
			}
		}
	}
	for name := range skip {
		if _, ok := registry[name]; !ok {
			return nil, nil, fmt.Errorf("unsupported module in --skip: %s", name)
		}
	}

	selected := make([]Module, 0, len(registry))
	for name, mod := range registry {
		if len(only) > 0 {
			if _, ok := only[name]; !ok {
				continue
			}
		}
		if _, ok := skip[name]; ok {
			continue
		}
		if _, ok := discovered[name]; !ok {
			continue
		}
		if opts.AnonOnly && !mod.SupportsAnonymous() {
			for _, target := range targets {
				if target.Service != mod.Name() {
					continue
				}
				skippedTargets = append(skippedTargets, SkippedFinding(target, "mode", "anon-only mode; "+mod.Name()+" has no anonymous auth"))
			}
			continue
		}
		selected = append(selected, mod)
	}

	sort.Slice(selected, func(i, j int) bool {
		return selected[i].Name() < selected[j].Name()
	})
	return selected, skippedTargets, nil
}
