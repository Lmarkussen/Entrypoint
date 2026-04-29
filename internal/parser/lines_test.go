package parser

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseNonCommentLinesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "communities.txt")
	if err := os.WriteFile(path, []byte("\n# comment\npublic\n monitor \n#private\nreadonly\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	got, err := ParseNonCommentLinesFile(path)
	if err != nil {
		t.Fatalf("ParseNonCommentLinesFile returned error: %v", err)
	}

	want := []string{"public", "monitor", "readonly"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected lines: got %v want %v", got, want)
	}
}
