package core

import "strings"

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

	return out
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
