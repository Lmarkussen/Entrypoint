package assets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBannerReturnsFirstReadableBanner(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "missing-banner")
	second := filepath.Join(dir, "banner")
	if err := os.WriteFile(second, []byte("ENTRYPOINT\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	got := loadBanner([]string{first, second})
	if got != "ENTRYPOINT\n" {
		t.Fatalf("unexpected banner: %q", got)
	}
}

func TestLoadBannerMissingReturnsEmpty(t *testing.T) {
	if got := loadBanner([]string{filepath.Join(t.TempDir(), "missing")}); got != "" {
		t.Fatalf("expected empty banner, got %q", got)
	}
}

func TestLoadTopCredsText(t *testing.T) {
	got, err := LoadTopCredsText()
	if err != nil {
		t.Fatalf("LoadTopCredsText returned error: %v", err)
	}
	if got == "" {
		t.Fatal("expected embedded top creds text")
	}
	if got[:11] != "admin:admin" {
		t.Fatalf("unexpected top creds prefix: %q", got)
	}
}
