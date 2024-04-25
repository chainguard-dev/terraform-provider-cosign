package provider

import (
	"context"

	"github.com/sigstore/cosign/v2/pkg/providers"

	_ "github.com/chainguard-dev/terraform-provider-cosign/internal/provider/interactive"
	_ "github.com/sigstore/cosign/v2/pkg/providers/envvar"
	_ "github.com/sigstore/cosign/v2/pkg/providers/filesystem"
	_ "github.com/sigstore/cosign/v2/pkg/providers/github"
	_ "github.com/sigstore/cosign/v2/pkg/providers/google"
)

// An impl that represents github.com/sigstore/cosign/pkg/providers/*.
type oidcProvider struct {
}

func (p *oidcProvider) Enabled(ctx context.Context) bool {
	return providers.Enabled(ctx)
}

func (p *oidcProvider) Provide(ctx context.Context, audience string) (string, error) {
	return providers.Provide(ctx, audience)
}
