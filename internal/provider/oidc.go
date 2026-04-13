package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/cosign/v3/pkg/providers"

	_ "github.com/chainguard-dev/terraform-provider-cosign/internal/provider/interactive"
	_ "github.com/sigstore/cosign/v3/pkg/providers/envvar"
	_ "github.com/sigstore/cosign/v3/pkg/providers/filesystem"
	_ "github.com/sigstore/cosign/v3/pkg/providers/github"
	_ "github.com/sigstore/cosign/v3/pkg/providers/google"
)

// oidcExpiryBuffer is subtracted from the token's exp claim to ensure we
// refresh before the token actually expires.
const oidcExpiryBuffer = 30 * time.Second

// OIDCProvider is what providers need to implement to participate in furnishing OIDC tokens.
type OIDCProvider interface {
	Enabled(ctx context.Context) bool
	Provide(ctx context.Context, audience string) (string, error)
}

// oidcProvider represents github.com/sigstore/cosign/pkg/providers/*.
// Caches the token until near its expiry so that back-to-back calls
// (e.g. legacy then bundle path in "both" mode) share a single auth
// prompt, while calls after token expiry get a fresh token.
type oidcProvider struct {
	mu     sync.Mutex
	token  string
	err    error
	expiry time.Time
}

func (p *oidcProvider) Enabled(ctx context.Context) bool {
	return providers.Enabled(ctx)
}

func (p *oidcProvider) Provide(ctx context.Context, audience string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" && p.err == nil && time.Now().Before(p.expiry) {
		return p.token, nil
	}

	p.token, p.err = providers.Provide(ctx, audience)
	if p.err != nil {
		return p.token, p.err
	}

	p.expiry = tokenExpiry(p.token)
	return p.token, nil
}

// tokenExpiry extracts the exp claim from a JWT token and returns the time
// minus a buffer. If the token can't be parsed, returns the current time
// (forcing a re-fetch on next call).
func tokenExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		// Not a valid JWT; disable caching so we re-fetch every time.
		fmt.Fprintln(os.Stderr, "Warning: OIDC token is not a valid JWT, token caching disabled")
		return time.Now()
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Can't decode payload; disable caching so we re-fetch every time.
		fmt.Fprintf(os.Stderr, "Warning: failed to decode OIDC token payload: %v, token caching disabled\n", err)
		return time.Now()
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		// Can't extract exp claim; disable caching so we re-fetch every time.
		fmt.Fprintf(os.Stderr, "Warning: failed to parse OIDC token claims: %v, token caching disabled\n", err)
		return time.Now()
	}
	if claims.Exp == 0 {
		// No exp claim; disable caching so we re-fetch every time.
		fmt.Fprintln(os.Stderr, "Warning: OIDC token has no exp claim, token caching disabled")
		return time.Now()
	}

	return time.Unix(claims.Exp, 0).Add(-oidcExpiryBuffer)
}
