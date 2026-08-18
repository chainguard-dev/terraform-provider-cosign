// Package chainguardcache provides OIDC tokens from the Chainguard token
// cache: the chainctl-convention layout at
// <user cache dir>/chainguard/<escaped audience>/oidc-token.
//
// It is intended for environments where that path is backed by a credential
// filesystem minting a fresh token on every read, so each signing operation
// presents a current token. Unlike ambient detection, enabling is explicit
// (TF_COSIGN_CHAINGUARD_TOKEN_CACHE): when set, an unreadable or empty token
// fails the operation instead of the provider chain silently skipping
// signing.
package chainguardcache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/v3/pkg/providers"
)

// envVar enables the provider. Any non-empty value enables it; a value that
// is an absolute path additionally overrides the cache root, replacing
// <user cache dir>/chainguard.
const envVar = "TF_COSIGN_CHAINGUARD_TOKEN_CACHE"

func init() {
	providers.Register("chainguard-token-cache", &provider{})
}

type provider struct{}

var _ providers.Interface = (*provider)(nil)

// Enabled implements providers.Interface.
func (p *provider) Enabled(context.Context) bool {
	return os.Getenv(envVar) != ""
}

// Provide implements providers.Interface.
func (p *provider) Provide(_ context.Context, audience string) (string, error) {
	root := os.Getenv(envVar)
	if !filepath.IsAbs(root) {
		dir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("chainguard token cache: resolving user cache dir: %w", err)
		}
		root = filepath.Join(dir, "chainguard")
	}
	// The chainctl cache convention names each audience directory with path
	// separators replaced, so the audience cannot traverse out of the root.
	path := filepath.Join(root, strings.ReplaceAll(audience, "/", "-"), "oidc-token")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("chainguard token cache: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("chainguard token cache: %s is empty", path)
	}
	return token, nil
}
