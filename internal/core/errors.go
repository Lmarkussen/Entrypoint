package core

import (
	"fmt"
	"strings"
)

const (
	AuthTypeInfrastructure = "infrastructure"
)

func NormalizeAndCollapseFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	type normalizedFinding struct {
		finding         Finding
		connectionLevel bool
	}

	items := make([]normalizedFinding, len(findings))
	for idx, finding := range findings {
		items[idx] = normalizedFinding{
			finding:         NormalizeFindingError(finding),
			connectionLevel: isConnectionLevelErrorFinding(finding),
		}
	}

	type collapseGroup struct {
		firstIndex int
		count      int
		finding    Finding
	}

	groups := make(map[string]collapseGroup)
	for idx, item := range items {
		if !item.connectionLevel || ClassifyFinding(item.finding) != "error" {
			continue
		}
		key := collapseKey(item.finding)
		group, ok := groups[key]
		if !ok {
			groups[key] = collapseGroup{
				firstIndex: idx,
				count:      1,
				finding:    item.finding,
			}
			continue
		}
		group.count++
		groups[key] = group
	}

	out := make([]Finding, 0, len(items))
	suppressed := make(map[string]struct{})
	for idx, item := range items {
		if item.connectionLevel && ClassifyFinding(item.finding) == "error" {
			key := collapseKey(item.finding)
			group := groups[key]
			if group.count > 1 {
				if _, seen := suppressed[key]; seen {
					continue
				}
				if group.firstIndex == idx {
					collapsed := group.finding
					collapsed.AuthType = AuthTypeInfrastructure
					collapsed.Username = ""
					collapsed.Password = ""
					collapsed.Evidence = ""
					out = append(out, collapsed)
					suppressed[key] = struct{}{}
					continue
				}
				continue
			}
		}
		out = append(out, item.finding)
	}

	return collapseRepeatedInvalidCredentialFailures(out)
}

func NormalizeFindingError(f Finding) Finding {
	if ClassifyFinding(f) != "error" {
		if !f.Success {
			f.Password = ""
		}
		return f
	}

	f.Password = ""
	f.Notes = normalizeOperatorErrorMessage(f.Notes)
	if isConnectionLevelErrorFinding(f) {
		f.Evidence = ""
	}
	return f
}

func normalizeOperatorErrorMessage(message string) string {
	normalized := strings.Join(strings.Fields(message), " ")
	lower := strings.ToLower(normalized)

	switch {
	case strings.Contains(lower, "operation not permitted"):
		return "local socket blocked / operation not permitted"
	case strings.Contains(lower, "no route to host"):
		return "no route to host"
	case strings.Contains(lower, "network is unreachable"), strings.Contains(lower, "network unreachable"):
		return "network unreachable"
	case strings.Contains(lower, "connection refused"):
		return "connection refused"
	case strings.Contains(lower, "connection reset by peer"), strings.Contains(lower, "connection reset"):
		return "connection reset"
	case strings.Contains(lower, "context deadline exceeded"),
		strings.Contains(lower, "i/o timeout"),
		strings.Contains(lower, "timed out"),
		lower == "timeout/no response",
		lower == "timeout":
		return "timeout"
	case strings.Contains(lower, "connection closed before login prompt"),
		strings.Contains(lower, "connection closed before password prompt"),
		strings.Contains(lower, "connection closed before prompt"),
		strings.Contains(lower, "timeout waiting for login prompt: eof"),
		strings.Contains(lower, "timeout waiting for password prompt: eof"):
		return "connection closed before prompt"
	case lower == "eof",
		strings.Contains(lower, "connection unexpectedly closed"),
		strings.Contains(lower, "closed network connection"),
		strings.Contains(lower, "connection closed by remote host"):
		return "connection closed"
	default:
		return normalized
	}
}

func isConnectionLevelErrorFinding(f Finding) bool {
	if ClassifyFinding(f) != "error" {
		return false
	}

	note := strings.ToLower(strings.Join(strings.Fields(f.Notes), " "))
	if note == "" {
		return false
	}

	if strings.HasPrefix(note, "connect failed:") ||
		strings.HasPrefix(note, "banner read failed:") ||
		strings.HasPrefix(note, "ssh handshake failed:") ||
		strings.HasPrefix(note, "session setup failed:") {
		return true
	}

	if strings.Contains(note, "dial tcp") ||
		strings.Contains(note, `post "http://`) ||
		strings.Contains(note, `post "https://`) ||
		note == "local socket blocked / operation not permitted" ||
		note == "connection refused" ||
		note == "timeout" ||
		note == "no route to host" ||
		note == "network unreachable" ||
		note == "connection reset" ||
		note == "connection closed" ||
		note == "connection closed before prompt" {
		return true
	}

	return false
}

func collapseKey(f Finding) string {
	return strings.Join([]string{f.Host, f.Service, f.Notes}, "\x00")
}

func collapseRepeatedInvalidCredentialFailures(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	validUsers := make(map[string]struct{})
	for _, finding := range findings {
		if finding.Success && finding.AuthType == "credential" {
			validUsers[credentialIdentityKey(finding)] = struct{}{}
		}
	}

	type invalidGroup struct {
		firstIndex int
		count      int
		finding    Finding
	}

	groups := make(map[string]invalidGroup)
	for idx, finding := range findings {
		summaryNote, family, ok := summarizeableInvalidCredentialReason(finding)
		if !ok {
			continue
		}
		if _, ok := validUsers[credentialIdentityKey(finding)]; ok {
			continue
		}

		key := invalidCredentialCollapseKey(finding, family)
		group, exists := groups[key]
		if !exists {
			collapsed := finding
			collapsed.Password = ""
			collapsed.Notes = summaryNote
			collapsed.Evidence = ""
			groups[key] = invalidGroup{
				firstIndex: idx,
				count:      1,
				finding:    collapsed,
			}
			continue
		}
		group.count++
		groups[key] = group
	}

	out := make([]Finding, 0, len(findings))
	emitted := make(map[string]struct{})
	for idx, finding := range findings {
		summaryNote, family, ok := summarizeableInvalidCredentialReason(finding)
		if !ok {
			out = append(out, finding)
			continue
		}
		if _, ok := validUsers[credentialIdentityKey(finding)]; ok {
			continue
		}

		key := invalidCredentialCollapseKey(finding, family)
		group := groups[key]
		if group.count <= 1 {
			out = append(out, finding)
			continue
		}
		if _, ok := emitted[key]; ok {
			continue
		}
		if group.firstIndex != idx {
			continue
		}

		collapsed := group.finding
		collapsed.Notes = fmt.Sprintf("%s; tried %d passwords", summaryNote, group.count)
		out = append(out, collapsed)
		emitted[key] = struct{}{}
	}

	return out
}

func summarizeableInvalidCredentialReason(f Finding) (string, string, bool) {
	if ClassifyFinding(f) != "invalid" || f.AuthType != "credential" {
		return "", "", false
	}

	note := strings.ToLower(strings.Join(strings.Fields(f.Notes), " "))
	if note == "" {
		return "", "", false
	}
	if containsAnyFold(note,
		"account locked",
		"account disabled",
		"user disabled",
		"password expired",
		"must change password",
		"change your password",
		"tls",
		"certificate",
		"protocol error",
		"connection refused",
		"timeout",
	) {
		return "", "", false
	}

	switch {
	case strings.Contains(note, "login failed"), strings.Contains(note, "login incorrect"):
		return "login failed", "auth-denied", true
	case strings.Contains(note, "authentication failed"), strings.Contains(note, "auth failed"):
		return "auth failed", "auth-denied", true
	case strings.Contains(note, "invalid credentials"):
		return "invalid credentials", "auth-denied", true
	case strings.Contains(note, "bind failed"):
		return "bind failed", "auth-denied", true
	case strings.Contains(note, "no valid credential"):
		return "no valid credential", "auth-denied", true
	case strings.Contains(note, "access denied"):
		return "access denied", "auth-denied", true
	default:
		return "", "", false
	}
}

func invalidCredentialCollapseKey(f Finding, family string) string {
	return strings.Join([]string{
		f.Host,
		fmt.Sprintf("%d", f.Port),
		f.Service,
		f.AuthType,
		f.Username,
		family,
	}, "\x00")
}

func credentialIdentityKey(f Finding) string {
	return strings.Join([]string{
		f.Host,
		fmt.Sprintf("%d", f.Port),
		f.Service,
		f.AuthType,
		f.Username,
	}, "\x00")
}

func containsAnyFold(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(strings.ToLower(s), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
