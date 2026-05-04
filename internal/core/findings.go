package core

import (
	"fmt"
	"strings"
)

const (
	SeverityValid = "valid"
	SeverityWarn  = "warning"
	SeverityError = "error"
	SeverityInfo  = "info"
)

func ValidFinding(target Target, authType, username, evidence, notes string) Finding {
	return Finding{
		Host:     target.Host,
		Port:     target.Port,
		Service:  target.Service,
		AuthType: authType,
		Username: username,
		Success:  true,
		Severity: SeverityValid,
		Evidence: evidence,
		Notes:    notes,
	}
}

func InvalidFinding(target Target, authType, username, evidence, notes string) Finding {
	return Finding{
		Host:     target.Host,
		Port:     target.Port,
		Service:  target.Service,
		AuthType: authType,
		Username: username,
		Success:  false,
		Severity: SeverityWarn,
		Evidence: evidence,
		Notes:    notes,
	}
}

func ErrorFinding(target Target, authType, username, evidence, notes string) Finding {
	return Finding{
		Host:     target.Host,
		Port:     target.Port,
		Service:  target.Service,
		AuthType: authType,
		Username: username,
		Success:  false,
		Severity: SeverityError,
		Evidence: evidence,
		Notes:    notes,
	}
}

func SkippedFinding(target Target, authType, notes string) Finding {
	return Finding{
		Host:     target.Host,
		Port:     target.Port,
		Service:  target.Service,
		AuthType: authType,
		Success:  false,
		Severity: SeverityInfo,
		Notes:    notes,
	}
}

func WithCredentialPassword(f Finding, password string) Finding {
	if !f.Success || f.AuthType != "credential" || strings.TrimSpace(password) == "" {
		return f
	}
	f.Password = password
	return f
}

func ClassifyFinding(f Finding) string {
	if f.Success {
		return "valid"
	}

	switch f.Severity {
	case SeverityError:
		return "error"
	case SeverityInfo:
		return "skipped"
	default:
		return "invalid"
	}
}

func ClassifyFindings(findings []Finding) FindingStats {
	stats := FindingStats{}
	for _, finding := range findings {
		if strings.Contains(finding.AuthType, "anon") || strings.Contains(finding.AuthType, "null") {
			if finding.Success {
				stats.Anonymous++
			}
		}

		switch ClassifyFinding(finding) {
		case "valid":
			stats.Valid++
		case "error":
			stats.Errors++
		case "skipped":
			stats.Skipped++
		default:
			stats.Invalid++
		}
	}
	return stats
}

func FindingSortKey(f Finding) string {
	return fmt.Sprintf("%s:%05d:%s:%d:%s:%s", f.Service, f.Port, f.Host, boolRank(f.Success), f.Severity, f.Username)
}

func boolRank(v bool) int {
	if v {
		return 0
	}
	return 1
}
