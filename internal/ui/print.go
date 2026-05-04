package ui

import (
	"fmt"
	"io"
	"net/netip"
	"regexp"
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

const priorityEvidenceMaxLen = 120

var priorityPasswordPattern = regexp.MustCompile(`(?i)(password|pass)=([^;\s]+)`)

type priorityEntry struct {
	hostPort string
	host     string
	port     int
	service  string
	auth     string
	identity string
	detail   string
}

func PrintSummary(w io.Writer, summary core.Summary, opts core.Options, credCount int) {
	fmt.Fprint(w, SummaryLine(summary, opts, credCount, true))
}

func PrintFinding(w io.Writer, finding core.Finding, redactSuccessPasswords bool) {
	fmt.Fprint(w, FindingLine(finding, true, redactSuccessPasswords))
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

func FindingLine(finding core.Finding, color bool, redactSuccessPasswords bool) string {
	label, statusColor := statusLabel(finding)
	detail := renderFindingDetail(finding, redactSuccessPasswords)
	return fmt.Sprintf("%s[%s]%s %-7s [%s] %-7s %s:%d   %s\n",
		colorCode(color, statusColor), label, colorCode(color, reset), strings.ToUpper(core.ClassifyFinding(finding)), authLabel(finding), finding.Service, finding.Host, finding.Port, detail)
}

func SuccessLogLine(finding core.Finding, redactSuccessPasswords bool) string {
	detail := renderFindingDetail(finding, redactSuccessPasswords)
	return fmt.Sprintf("VALID [%s] %s %s:%d %s\n",
		authLabel(finding), finding.Service, finding.Host, finding.Port, detail)
}

func TotalsLine(stats core.FindingStats, color bool) string {
	return fmt.Sprintf("%s[*]%s totals valid=%d invalid=%d errors=%d skipped=%d anonymous=%d\n",
		colorCode(color, cyan), colorCode(color, reset), stats.Valid, stats.Invalid, stats.Errors, stats.Skipped, stats.Anonymous)
}

func RunSummaryBlock(findings []core.Finding, color bool, redactSuccessPasswords bool) string {
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
			entry := summaryValidEntry(finding, redactSuccessPasswords)
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

func PriorityTargetsBlock(findings []core.Finding, color bool, redactSuccessPasswords bool) string {
	groups := map[string][]priorityEntry{
		"HIGH":   {},
		"MEDIUM": {},
		"LOW":    {},
	}

	for _, finding := range findings {
		if core.ClassifyFinding(finding) != "valid" {
			continue
		}
		priority := findingPriority(finding.Service)
		if priority == "" {
			continue
		}

		groups[priority] = append(groups[priority], priorityEntry{
			hostPort: fmt.Sprintf("%s:%d", finding.Host, finding.Port),
			host:     finding.Host,
			port:     finding.Port,
			service:  finding.Service,
			auth:     authLabel(finding),
			identity: priorityIdentity(finding, redactSuccessPasswords),
			detail:   priorityDetail(finding, redactSuccessPasswords),
		})
	}

	hasValid := false
	for _, entries := range groups {
		if len(entries) > 0 {
			hasValid = true
			break
		}
	}

	var builder strings.Builder
	builder.WriteString(colorCode(color, cyan))
	builder.WriteString("==== PRIORITY TARGETS ====\n")
	builder.WriteString(colorCode(color, reset))
	if !hasValid {
		builder.WriteString("none\n")
		return builder.String()
	}

	for _, level := range []string{"HIGH", "MEDIUM", "LOW"} {
		entries := groups[level]
		sort.Slice(entries, func(i, j int) bool {
			return lessPriorityEntry(entries[i], entries[j])
		})

		builder.WriteString(level)
		builder.WriteString(":\n")
		for _, entry := range entries {
			builder.WriteString(fmt.Sprintf("  %-21s %-7s [%s] %-16s %s\n",
				entry.hostPort,
				entry.service,
				entry.auth,
				entry.identity,
				entry.detail,
			))
		}
		if level != "LOW" {
			builder.WriteByte('\n')
		}
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

func renderFindingDetail(f core.Finding, redactSuccessPasswords bool) string {
	parts := make([]string, 0, 4)
	if authLabel(f) == "C" {
		switch {
		case f.Username != "":
			parts = append(parts, "user="+f.Username)
		case shouldShowSuccessPassword(f, redactSuccessPasswords):
			parts = append(parts, "password-only")
		}
		if passwordPart := successPasswordPart(f, redactSuccessPasswords); passwordPart != "" {
			parts = append(parts, passwordPart)
		}
	}
	if f.Notes != "" && !(shouldShowSuccessPassword(f, redactSuccessPasswords) && f.Notes == "password-only auth") {
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

func summaryValidEntry(f core.Finding, redactSuccessPasswords bool) string {
	principal := summaryPrincipal(f, redactSuccessPasswords)
	if passwordPart := successPasswordPart(f, redactSuccessPasswords); passwordPart != "" {
		principal += " " + passwordPart
	}
	return fmt.Sprintf("%-7s [%s] %s", f.Service, authLabel(f), principal)
}

func summaryPrincipal(f core.Finding, redactSuccessPasswords bool) string {
	if f.Username != "" && f.Username != "<anonymous>" {
		return f.Username
	}
	if authLabel(f) == "C" && shouldShowSuccessPassword(f, redactSuccessPasswords) {
		return "password-only"
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

func findingPriority(service string) string {
	switch service {
	case "winrm", "winrm-ssl", "ssh", "telnet", "mssql":
		return "HIGH"
	case "smb", "ftp", "redis", "nfs", "rsync":
		return "MEDIUM"
	case "ldap", "ldaps", "snmp":
		return "LOW"
	default:
		return ""
	}
}

func priorityIdentity(f core.Finding, redactSuccessPasswords bool) string {
	if authLabel(f) == "C" {
		if f.Username != "" {
			return f.Username
		}
		if shouldShowSuccessPassword(f, redactSuccessPasswords) {
			return "password-only"
		}
		return "<unknown>"
	}

	switch f.Service {
	case "redis":
		return "no-auth"
	case "snmp":
		if f.Username != "" {
			return f.Username
		}
		if community := prefixedValue(f.Notes, "community="); community != "" {
			return community
		}
		return "anonymous"
	case "smb":
		if f.Username != "" {
			return f.Username
		}
		if f.AuthType == "null-session" || containsAnyFold(f.Notes, "guest", "null session") || containsAnyFold(f.Evidence, "guest", "null session") {
			return "null/guest"
		}
		return "anonymous"
	case "ftp", "ldap", "ldaps", "nfs", "rsync":
		return "anonymous"
	default:
		if f.Username != "" && f.Username != "<anonymous>" {
			return f.Username
		}
		if f.AuthType == "null-session" {
			return "null/guest"
		}
		return "anonymous"
	}
}

func priorityDetail(f core.Finding, redactSuccessPasswords bool) string {
	parts := make([]string, 0, 2)
	if passwordPart := successPasswordPart(f, redactSuccessPasswords); passwordPart != "" {
		parts = append(parts, passwordPart)
	}
	if detail := firstNonEmpty(f.Evidence, f.Notes); detail != "" {
		parts = append(parts, detail)
	}
	detail := strings.Join(parts, "; ")
	detail = strings.Join(strings.Fields(detail), " ")
	if redactSuccessPasswords {
		detail = priorityPasswordPattern.ReplaceAllString(detail, "$1=<redacted>")
	}
	return truncateText(detail, priorityEvidenceMaxLen)
}

func shouldShowSuccessPassword(f core.Finding, redactSuccessPasswords bool) bool {
	return f.Success && f.AuthType == "credential" && strings.TrimSpace(f.Password) != "" && !redactSuccessPasswords
}

func successPasswordPart(f core.Finding, redactSuccessPasswords bool) string {
	if !shouldShowSuccessPassword(f, redactSuccessPasswords) {
		return ""
	}
	return "password=" + f.Password
}

func truncateText(value string, maxLen int) string {
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	if maxLen <= 3 {
		return value[:maxLen]
	}
	return strings.TrimSpace(value[:maxLen-3]) + "..."
}

func lessPriorityEntry(left, right priorityEntry) bool {
	leftAddr, leftErr := netip.ParseAddr(left.host)
	rightAddr, rightErr := netip.ParseAddr(right.host)
	switch {
	case leftErr == nil && rightErr == nil:
		if leftAddr != rightAddr {
			return leftAddr.Less(rightAddr)
		}
	case left.host != right.host:
		return left.host < right.host
	}

	if left.service != right.service {
		return left.service < right.service
	}
	if left.port != right.port {
		return left.port < right.port
	}
	if left.identity != right.identity {
		return left.identity < right.identity
	}
	return left.detail < right.detail
}

func prefixedValue(raw, prefix string) string {
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), strings.ToLower(prefix)) {
			return strings.TrimSpace(part[len(prefix):])
		}
	}
	return ""
}

func containsAnyFold(raw string, patterns ...string) bool {
	value := strings.ToLower(raw)
	for _, pattern := range patterns {
		if strings.Contains(value, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}
