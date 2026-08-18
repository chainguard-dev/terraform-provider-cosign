package chainguardcache

import (
	"os"
	"path/filepath"
	"testing"
)

func writeToken(t *testing.T, root, audience, token string) {
	t.Helper()
	dir := filepath.Join(root, audience)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oidc-token"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnabled(t *testing.T) {
	p := &provider{}

	t.Run("disabled without the env var", func(t *testing.T) {
		t.Setenv(envVar, "")
		if p.Enabled(t.Context()) {
			t.Error("Enabled() = true, want false")
		}
	})

	t.Run("enabled with any non-empty value", func(t *testing.T) {
		t.Setenv(envVar, "1")
		if !p.Enabled(t.Context()) {
			t.Error("Enabled() = false, want true")
		}
	})
}

func TestProvide(t *testing.T) {
	p := &provider{}

	t.Run("reads from the default cache location", func(t *testing.T) {
		// os.UserCacheDir resolves from XDG_CACHE_HOME on linux and HOME on
		// darwin; point both at temp dirs and write where it answers.
		t.Setenv("XDG_CACHE_HOME", t.TempDir())
		t.Setenv("HOME", t.TempDir())
		t.Setenv(envVar, "1")

		root, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		writeToken(t, filepath.Join(root, "chainguard"), "sigstore", "tok-abc\n")

		got, err := p.Provide(t.Context(), "sigstore")
		if err != nil {
			t.Fatalf("Provide: %v", err)
		}
		if got != "tok-abc" {
			t.Errorf("Provide() = %q, want %q", got, "tok-abc")
		}
	})

	t.Run("absolute env value overrides the cache root", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv(envVar, root)
		writeToken(t, root, "sigstore", "tok-override")

		got, err := p.Provide(t.Context(), "sigstore")
		if err != nil {
			t.Fatalf("Provide: %v", err)
		}
		if got != "tok-override" {
			t.Errorf("Provide() = %q, want %q", got, "tok-override")
		}
	})

	t.Run("escapes audience path separators like chainctl", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv(envVar, root)
		writeToken(t, root, "https:--issuer.example.dev", "tok-esc")

		got, err := p.Provide(t.Context(), "https://issuer.example.dev")
		if err != nil {
			t.Fatalf("Provide: %v", err)
		}
		if got != "tok-esc" {
			t.Errorf("Provide() = %q, want %q", got, "tok-esc")
		}
	})

	t.Run("missing token errors instead of skipping", func(t *testing.T) {
		t.Setenv(envVar, t.TempDir())
		if _, err := p.Provide(t.Context(), "sigstore"); err == nil {
			t.Error("Provide() = nil error, want read failure")
		}
	})

	t.Run("empty token errors", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv(envVar, root)
		writeToken(t, root, "sigstore", "  \n")
		if _, err := p.Provide(t.Context(), "sigstore"); err == nil {
			t.Error("Provide() = nil error, want empty-token failure")
		}
	})
}
