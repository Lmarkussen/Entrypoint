package modules

import (
	"fmt"
	"strings"

	"entrypoint/internal/core"
)

func displayUser(cred core.Credential) string {
	if cred.Domain != "" && cred.Username != "" {
		return fmt.Sprintf("%s\\%s", cred.Domain, cred.Username)
	}
	if cred.Username != "" {
		return cred.Username
	}
	if cred.Password != "" {
		return "<empty-username>"
	}
	return "<anonymous>"
}

func normalizeEvidence(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.Join(strings.Fields(value), " ")
}
