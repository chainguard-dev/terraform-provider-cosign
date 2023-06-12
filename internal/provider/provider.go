package provider

import (
	"context"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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
		ropts:    ropts,
		keychain: kc,
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
