package provider

import (
	"context"

	"github.com/sigstore/cosign/v2/pkg/providers"

	_ "github.com/chainguard-dev/terraform-provider-cosign/internal/provider/interactive"
	_ "github.com/sigstore/cosign/v2/pkg/providers/filesystem"
	_ "github.com/sigstore/cosign/v2/pkg/providers/github"
)

// An impl that represents github.com/sigstore/cosign/pkg/providers/github.
type oidcProvider struct {
}

func (p *oidcProvider) Enabled(ctx context.Context) bool {
	return providers.Enabled(ctx)
}

func (p *oidcProvider) Provide(ctx context.Context, audience string) (string, error) {
	return providers.Provide(ctx, audience)
}
