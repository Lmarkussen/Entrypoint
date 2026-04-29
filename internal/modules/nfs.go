package modules

import (
	"context"
	"errors"
	"os/exec"
	"sort"
	"strings"
	"time"

	"entrypoint/internal/core"
)

type nfsModule struct{}

type nfsAttemptResult struct {
	exports []string
	valid   bool
	notes   string
}

var nfsAttemptFunc = checkNFSAttempt

func NewNFSModule() core.Module {
	return nfsModule{}
}

func (nfsModule) Name() string { return "nfs" }

func (nfsModule) Ports() []int { return []int{2049} }

func (nfsModule) SupportsAnonymous() bool { return true }

func (nfsModule) SupportsCredentials() bool { return false }

func (nfsModule) Check(ctx context.Context, target core.Target, _ []core.Credential, opts core.Options) []core.Finding {
	if !opts.IncludeAnon && !opts.AnonOnly {
		return []core.Finding{core.SkippedFinding(target, "anonymous", "anonymous/null checks disabled; nfs uses export enumeration")}
	}

	result, err := nfsAttemptFunc(ctx, target, opts.Timeout)
	if err != nil {
		return []core.Finding{core.ErrorFinding(target, "anonymous", "", "", sanitizeNFSError(err))}
	}
	if result.valid {
		return []core.Finding{core.ValidFinding(target, "anonymous", "", formatNFSExportsEvidence(result.exports), result.notes)}
	}
	return []core.Finding{core.InvalidFinding(target, "anonymous", "", "", "no exports visible")}
}

func checkNFSAttempt(ctx context.Context, target core.Target, timeout time.Duration) (nfsAttemptResult, error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if _, err := exec.LookPath("showmount"); err != nil {
		return nfsAttemptResult{}, errors.New("showmount not found")
	}

	cmd := exec.CommandContext(commandCtx, "showmount", "-e", target.Host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if commandCtx.Err() != nil {
			return nfsAttemptResult{}, commandCtx.Err()
		}
		message := normalizeEvidence(string(output))
		if message == "" {
			message = normalizeEvidence(err.Error())
		}
		return nfsAttemptResult{}, errors.New(message)
	}

	exports, access := parseShowmountExports(string(output))
	if len(exports) == 0 {
		return nfsAttemptResult{}, nil
	}

	notes := ""
	switch access {
	case "world-readable":
		notes = "access appears world-readable"
	case "restricted":
		notes = "access appears restricted"
	}

	return nfsAttemptResult{
		exports: exports,
		valid:   true,
		notes:   notes,
	}, nil
}

func parseShowmountExports(raw string) ([]string, string) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	exports := make([]string, 0)
	worldReadable := false
	restricted := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "export list for ") || strings.HasPrefix(lower, "exports list on ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		exportPath := fields[0]
		if !strings.HasPrefix(exportPath, "/") {
			continue
		}
		exports = append(exports, exportPath)
		if len(fields) == 1 {
			restricted = true
			continue
		}
		for _, access := range fields[1:] {
			trimmed := strings.TrimSpace(access)
			if trimmed == "*" || strings.Contains(trimmed, "(everyone)") || strings.Contains(trimmed, "(world)") {
				worldReadable = true
			} else {
				restricted = true
			}
		}
	}

	sort.Strings(exports)
	exports = dedupeStrings(exports)

	switch {
	case worldReadable && !restricted:
		return exports, "world-readable"
	case restricted:
		return exports, "restricted"
	default:
		return exports, ""
	}
}

func formatNFSExportsEvidence(exports []string) string {
	if len(exports) == 0 {
		return ""
	}
	return "exports=" + strings.Join(exports, ",")
}

func sanitizeNFSError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout/no response"
	case errors.Is(err, exec.ErrNotFound):
		return "showmount not found"
	}

	message := strings.ToLower(strings.Join(strings.Fields(err.Error()), " "))
	if strings.Contains(message, "timed out") || strings.Contains(message, "timeout") {
		return "timeout/no response"
	}
	return strings.Join(strings.Fields(err.Error()), " ")
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
