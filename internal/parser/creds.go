package parser

import (
	"bufio"
	"fmt"
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

	scanner := bufio.NewScanner(file)
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
