package assets

import (
	_ "embed"
	"errors"
	"strings"
)

//go:embed top_creds.txt
var topCredsText string

func LoadTopCredsText() (string, error) {
	if strings.TrimSpace(topCredsText) == "" {
		return "", errors.New("internal/assets/top_creds.txt is empty")
	}
	return topCredsText, nil
}
