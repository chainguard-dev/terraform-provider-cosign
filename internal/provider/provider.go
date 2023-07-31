package provider

import (
	"context"
	"net/url"
	"sync"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/internal/secant/fulcio"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/sigstore/fulcio/pkg/api"
	rclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"go.uber.org/ratelimit"
)

// Ensure Provider satisfies various provider interfaces.
var _ provider.Provider = &Provider{}

type Provider struct {
	version string
}

// ProviderModel describes the provider data model.
type ProviderModel struct {
}

type ProviderOpts struct {
	ropts    []remote.Option
	keychain authn.Keychain

	oidc fulcio.OIDCProvider

	sync.Mutex

	// Keyed off fulcio URL.
	signers map[string]*fulcio.SignerVerifier

	// Keyed off rekor URL.
	rekorClients map[string]*client.Rekor

	// Client-side rate limiting to avoid rekor 429s.
	limiter ratelimit.Limiter
}

func (p *ProviderOpts) rekorClient(rekorUrl string) (*client.Rekor, error) {
	p.Lock()
	defer p.Unlock()

	if rekorClient, ok := p.rekorClients[rekorUrl]; ok {
		return rekorClient, nil
	}

	rekorClient, err := rclient.GetRekorClient(rekorUrl, rclient.WithUserAgent("terraform-provider-cosign"))
	if err != nil {
		return nil, err
	}

	p.rekorClients[rekorUrl] = rekorClient
	return rekorClient, nil
}

func (p *ProviderOpts) signerVerifier(fulcioUrl string) (*fulcio.SignerVerifier, error) {
	p.Lock()
	defer p.Unlock()

	if sv, ok := p.signers[fulcioUrl]; ok {
		return sv, nil
	}

	furl, err := url.Parse(fulcioUrl)
	if err != nil {
		return nil, err
	}
	fulcioClient := api.NewClient(furl, api.WithUserAgent("terraform-provider-cosign"))
	sv, err := fulcio.NewSigner(p.oidc, fulcioClient)
	if err != nil {
		return nil, err
	}

	p.signers[fulcioUrl] = sv
	return sv, nil
}

func (p *ProviderOpts) withContext(ctx context.Context) []remote.Option {
	return append([]remote.Option{remote.WithContext(ctx)}, p.ropts...)
}

func (p *Provider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cosign"
	resp.Version = p.version
}

func (p *Provider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data ProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	kc := authn.NewMultiKeychain(google.Keychain, authn.DefaultKeychain)
	ropts := []remote.Option{
		remote.WithAuthFromKeychain(kc),
		remote.WithUserAgent("terraform-provider-apko/" + p.version),
	}

	puller, err := remote.NewPuller(ropts...)
	if err != nil {
		resp.Diagnostics.AddError("Configuring cosign provider options", err.Error())
		return
	}
	pusher, err := remote.NewPusher(ropts...)
	if err != nil {
		resp.Diagnostics.AddError("Configuring cosign provider options", err.Error())
		return
	}
	ropts = append(ropts, remote.Reuse(puller), remote.Reuse(pusher))

	opts := &ProviderOpts{
		ropts:        ropts,
		keychain:     kc,
		oidc:         &oidcProvider{},
		signers:      map[string]*fulcio.SignerVerifier{},
		rekorClients: map[string]*client.Rekor{},
		// A little bird told me that rekor allows 500 requests per minute.
		limiter: ratelimit.New(500, ratelimit.Per(time.Minute), ratelimit.WithoutSlack),
	}

	// Make provider opts available to resources and data sources.
	resp.ResourceData = opts
	resp.DataSourceData = opts
}

func (p *Provider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAttestResource,
		NewSignResource,
		NewCopyResource,
	}
}

func (p *Provider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewVerifyDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{
			version: version,
		}
	}
}
