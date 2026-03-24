package provider

import (
	"context"
	"sync"

	"github.com/sigstore/cosign/v3/pkg/providers"

	_ "github.com/chainguard-dev/terraform-provider-cosign/internal/provider/interactive"
	_ "github.com/sigstore/cosign/v3/pkg/providers/envvar"
	_ "github.com/sigstore/cosign/v3/pkg/providers/filesystem"
	_ "github.com/sigstore/cosign/v3/pkg/providers/github"
	_ "github.com/sigstore/cosign/v3/pkg/providers/google"
)

// An impl that represents github.com/sigstore/cosign/pkg/providers/*.
type oidcProvider struct {
	once  sync.Once
	token string
	err   error
}

func (p *oidcProvider) Enabled(ctx context.Context) bool {
	return providers.Enabled(ctx)
}

// Provide fetches an OIDC token exactly once and caches it.
// Both the legacy fulcio.SignerVerifier and the BundleSigner paths call this,
// so caching here ensures at most one authentication prompt per provider lifecycle.
func (p *oidcProvider) Provide(ctx context.Context, audience string) (string, error) {
	p.once.Do(func() {
		p.token, p.err = providers.Provide(ctx, audience)
	})
	return p.token, p.err
}
