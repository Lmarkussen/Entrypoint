package assets

import (
	"os"
	"path/filepath"
)

func LoadBanner() string {
	return loadBanner(candidatePaths())
}

func loadBanner(paths []string) string {
	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		return string(data)
	}
	return ""
}

func candidatePaths() []string {
	paths := make([]string, 0, 2)

	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, "internal", "assets", "banner"))
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		paths = append(paths, filepath.Join(exeDir, "..", "internal", "assets", "banner"))
	}

	return paths
}
