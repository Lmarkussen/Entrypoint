package parser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"entrypoint/internal/core"
)

func ParseCredentialsFile(path string) ([]core.Credential, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParseCredentials(file)
}

func ParseCredentials(reader io.Reader) ([]core.Credential, error) {
	return parseCredentialsScanner(bufio.NewScanner(reader))
}

func MergeCredentials(groups ...[]core.Credential) []core.Credential {
	seen := make(map[string]struct{})
	merged := make([]core.Credential, 0)

	for _, group := range groups {
		for _, cred := range group {
			key := credentialKey(cred)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, cred)
		}
	}

	return merged
}

func parseCredentialsScanner(scanner *bufio.Scanner) ([]core.Credential, error) {
	creds := make([]core.Credential, 0)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cred, err := ParseCredentialLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		creds = append(creds, cred)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return creds, nil
}

func credentialKey(cred core.Credential) string {
	return cred.Domain + "\x00" + cred.Username + "\x00" + cred.Password
}

func ParseCredentialLine(line string) (core.Credential, error) {
	userPart, password, ok := strings.Cut(line, ":")
	if !ok {
		return core.Credential{}, fmt.Errorf("invalid credential format %q", line)
	}

	cred := core.Credential{Password: password}

	if domain, username, ok := strings.Cut(userPart, `\`); ok {
		cred.Domain = domain
		cred.Username = username
		return cred, nil
	}
	if domain, username, ok := strings.Cut(userPart, `/`); ok {
		cred.Domain = domain
		cred.Username = username
		return cred, nil
	}

	cred.Username = userPart
	return cred, nil
}
