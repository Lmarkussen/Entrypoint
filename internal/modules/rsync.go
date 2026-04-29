package modules

import (
	"context"
	"errors"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"entrypoint/internal/core"
)

type rsyncModule struct{}

type rsyncAttemptResult struct {
	modules []string
	valid   bool
}

var rsyncAttemptFunc = checkRsyncAttempt

func NewRsyncModule() core.Module {
	return rsyncModule{}
}

func (rsyncModule) Name() string { return "rsync" }

func (rsyncModule) Ports() []int { return []int{873} }

func (rsyncModule) SupportsAnonymous() bool { return true }

func (rsyncModule) SupportsCredentials() bool { return false }

func (rsyncModule) Check(ctx context.Context, target core.Target, _ []core.Credential, opts core.Options) []core.Finding {
	if !opts.IncludeAnon && !opts.AnonOnly {
		return []core.Finding{core.SkippedFinding(target, "anonymous", "anonymous/null checks disabled; rsync uses module listing")}
	}

	result, err := rsyncAttemptFunc(ctx, target, opts.Timeout)
	if err != nil {
		if isRsyncInvalidError(err) {
			return []core.Finding{core.InvalidFinding(target, "anonymous", "", "", sanitizeRsyncInvalid(err))}
		}
		return []core.Finding{core.ErrorFinding(target, "anonymous", "", "", sanitizeRsyncError(err))}
	}
	if result.valid {
		return []core.Finding{core.ValidFinding(target, "anonymous", "", formatRsyncModulesEvidence(result.modules), "")}
	}
	return []core.Finding{core.InvalidFinding(target, "anonymous", "", "", "no modules visible")}
}

func checkRsyncAttempt(ctx context.Context, target core.Target, timeout time.Duration) (rsyncAttemptResult, error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if _, err := exec.LookPath("rsync"); err != nil {
		return rsyncAttemptResult{}, errors.New("rsync not found")
	}

	seconds := int(timeout.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}

	cmd := exec.CommandContext(
		commandCtx,
		"rsync",
		"--no-motd",
		"--contimeout="+strconv.Itoa(seconds),
		"--timeout="+strconv.Itoa(seconds),
		"rsync://"+target.Host+":"+strconv.Itoa(target.Port)+"/",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if commandCtx.Err() != nil {
			return rsyncAttemptResult{}, commandCtx.Err()
		}
		message := normalizeEvidence(string(output))
		if message == "" {
			message = normalizeEvidence(err.Error())
		}
		return rsyncAttemptResult{}, errors.New(message)
	}

	modules := parseRsyncModules(string(output))
	if len(modules) == 0 {
		return rsyncAttemptResult{}, nil
	}

	return rsyncAttemptResult{
		modules: modules,
		valid:   true,
	}, nil
}

func parseRsyncModules(raw string) []string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	modules := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		modules = append(modules, name)
	}

	sort.Strings(modules)
	return dedupeStrings(modules)
}

func formatRsyncModulesEvidence(modules []string) string {
	if len(modules) == 0 {
		return ""
	}
	return "modules=" + strings.Join(modules, ",")
}

func sanitizeRsyncError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout/no response"
	case errors.Is(err, exec.ErrNotFound):
		return "rsync not found"
	}

	message := strings.ToLower(strings.Join(strings.Fields(err.Error()), " "))
	switch {
	case strings.Contains(message, "timed out"), strings.Contains(message, "timeout"), strings.Contains(message, "no response"):
		return "timeout/no response"
	case strings.Contains(message, "connection refused"):
		return "connection refused"
	case strings.Contains(message, "connection unexpectedly closed"):
		return "connection closed"
	default:
		return strings.Join(strings.Fields(err.Error()), " ")
	}
}

func isRsyncInvalidError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(strings.Join(strings.Fields(err.Error()), " "))
	return strings.Contains(message, "@error") ||
		strings.Contains(message, "access denied") ||
		strings.Contains(message, "auth failed") ||
		strings.Contains(message, "authentication failed") ||
		strings.Contains(message, "module list disabled")
}

func sanitizeRsyncInvalid(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(strings.Join(strings.Fields(err.Error()), " "))
	switch {
	case strings.Contains(message, "module list disabled"):
		return "no modules visible"
	case strings.Contains(message, "access denied"), strings.Contains(message, "auth failed"), strings.Contains(message, "authentication failed"):
		return "no modules visible"
	case strings.Contains(message, "@error"):
		return "no modules visible"
	default:
		return "no modules visible"
	}
}
