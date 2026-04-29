package parser

import (
	"bufio"
	"os"
	"strings"
)

func ParseNonCommentLinesFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	values := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		values = append(values, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}
