package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"entrypoint/internal/core"
)

const (
	reset  = "\033[0m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	cyan   = "\033[36m"
)

func PrintSummary(w io.Writer, summary core.Summary, opts core.Options, credCount int) {
	fmt.Fprint(w, SummaryLine(summary, opts, credCount, true))
}

func PrintFinding(w io.Writer, finding core.Finding) {
	fmt.Fprint(w, FindingLine(finding, true))
}

func PrintTotals(w io.Writer, stats core.FindingStats) {
	fmt.Fprint(w, TotalsLine(stats, true))
}

func SummaryLine(summary core.Summary, opts core.Options, credCount int, color bool) string {
	services := append([]string(nil), summary.SelectedServices...)
	sort.Strings(services)
	return fmt.Sprintf("%s[*]%s targets=%d services=%s creds=%d anon=%t anon_only=%t safe=%t stop_on_valid=%t\n",
		colorCode(color, cyan), colorCode(color, reset), summary.TotalTargets, strings.Join(services, ","), credCount, opts.IncludeAnon, opts.AnonOnly, opts.SafeMode, opts.StopOnValid)
}

func FindingLine(finding core.Finding, color bool) string {
	label, statusColor := statusLabel(finding)
	detail := renderFindingDetail(finding)
	return fmt.Sprintf("%s[%s]%s %-7s [%s] %-7s %s:%d   %s\n",
		colorCode(color, statusColor), label, colorCode(color, reset), strings.ToUpper(core.ClassifyFinding(finding)), authLabel(finding), finding.Service, finding.Host, finding.Port, detail)
}

func SuccessLogLine(finding core.Finding) string {
	detail := renderFindingDetail(finding)
	return fmt.Sprintf("VALID [%s] %s %s:%d %s\n",
		authLabel(finding), finding.Service, finding.Host, finding.Port, detail)
}

func TotalsLine(stats core.FindingStats, color bool) string {
	return fmt.Sprintf("%s[*]%s totals valid=%d invalid=%d errors=%d skipped=%d anonymous=%d\n",
		colorCode(color, cyan), colorCode(color, reset), stats.Valid, stats.Invalid, stats.Errors, stats.Skipped, stats.Anonymous)
}

func RunSummaryBlock(findings []core.Finding, color bool) string {
	type serviceCounts struct {
		valid   int
		invalid int
		errors  int
		skipped int
	}

	validByHost := make(map[string][]string)
	validSeen := make(map[string]struct{})
	serviceTotals := make(map[string]serviceCounts)

	for _, finding := range findings {
		if finding.Service == "" {
			continue
		}

		counts := serviceTotals[finding.Service]
		switch core.ClassifyFinding(finding) {
		case "valid":
			counts.valid++
			entry := summaryValidEntry(finding)
			key := finding.Host + "\x00" + entry
			if _, ok := validSeen[key]; !ok {
				validSeen[key] = struct{}{}
				validByHost[finding.Host] = append(validByHost[finding.Host], entry)
			}
		case "error":
			counts.errors++
		case "skipped":
			counts.skipped++
		default:
			counts.invalid++
		}
		serviceTotals[finding.Service] = counts
	}

	hosts := make([]string, 0, len(validByHost))
	for host := range validByHost {
		hosts = append(hosts, host)
		sort.Strings(validByHost[host])
	}
	sort.Strings(hosts)

	services := make([]string, 0, len(serviceTotals))
	maxServiceLen := len("service")
	for service := range serviceTotals {
		services = append(services, service)
		if len(service) > maxServiceLen {
			maxServiceLen = len(service)
		}
	}
	sort.Strings(services)

	var builder strings.Builder
	builder.WriteString(colorCode(color, cyan))
	builder.WriteString("==== SUMMARY ====\n")
	builder.WriteString(colorCode(color, reset))
	builder.WriteString("Valid access:\n")
	if len(hosts) == 0 {
		builder.WriteString("  none\n")
	} else {
		for _, host := range hosts {
			builder.WriteString(host)
			builder.WriteString(":\n")
			for _, entry := range validByHost[host] {
				builder.WriteString("  ")
				builder.WriteString(entry)
				builder.WriteByte('\n')
			}
		}
	}

	builder.WriteString("\nService counts:\n")
	if len(services) == 0 {
		builder.WriteString("  none\n")
		return builder.String()
	}

	format := fmt.Sprintf("%%-%ds valid=%%d invalid=%%d errors=%%d skipped=%%d\n", maxServiceLen)
	for _, service := range services {
		counts := serviceTotals[service]
		builder.WriteString(fmt.Sprintf(format, service, counts.valid, counts.invalid, counts.errors, counts.skipped))
	}

	return builder.String()
}

func BannerText(text string, color bool) string {
	if text == "" {
		return ""
	}
	if !color {
		return text
	}
	return green + text + reset
}

func statusLabel(f core.Finding) (string, string) {
	switch core.ClassifyFinding(f) {
	case "valid":
		return "+", green
	case "error":
		return "!", red
	case "skipped":
		return "*", cyan
	default:
		return "-", yellow
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func authLabel(f core.Finding) string {
	switch f.AuthType {
	case "anonymous", "null-session":
		return "A"
	case "credential":
		return "C"
	default:
		return "I"
	}
}

func renderFindingDetail(f core.Finding) string {
	parts := make([]string, 0, 3)
	if authLabel(f) == "C" && f.Username != "" {
		parts = append(parts, "user="+f.Username)
	}
	if f.Notes != "" {
		parts = append(parts, f.Notes)
	}
	if f.Evidence != "" {
		parts = append(parts, f.Evidence)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ")
}

func colorCode(enabled bool, code string) string {
	if !enabled {
		return ""
	}
	return code
}

func summaryValidEntry(f core.Finding) string {
	return fmt.Sprintf("%-7s [%s] %s", f.Service, authLabel(f), summaryPrincipal(f))
}

func summaryPrincipal(f core.Finding) string {
	if f.Username != "" && f.Username != "<anonymous>" {
		return f.Username
	}
	switch f.AuthType {
	case "null-session":
		return "null-session"
	case "anonymous":
		return "anonymous"
	default:
		return "<unknown>"
	}
}
