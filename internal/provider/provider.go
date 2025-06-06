package provider

import (
	"context"
	"net/url"
	"sync"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/fulcio"
	rclient "github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/rekor/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/rekor/pkg/generated/client"
)

// Ensure Provider satisfies various provider interfaces.
var _ provider.Provider = &Provider{}

type Provider struct {
	version string
}

// ProviderModel describes the provider data model.
type ProviderModel struct {
	DefaultAttestationEntryType types.String `tfsdk:"default_attestation_entry_type"`
}

type ProviderOpts struct {
	ropts                       []remote.Option
	keychain                    authn.Keychain
	defaultAttestationEntryType string

	oidc fulcio.OIDCProvider

	sync.Mutex

	// Keyed off fulcio URL.
	signers map[string]*fulcio.SignerVerifier

	// Keyed off rekor URL.
	rekorClients map[string]*client.Rekor
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
		Attributes: map[string]schema.Attribute{
			"default_attestation_entry_type": schema.StringAttribute{
				MarkdownDescription: "Default Rekor entry type to use for attestations. Valid values are 'intoto' (default) or 'dsse'.",
				Optional:            true,
				Validators:          []validator.String{EntryTypeValidator{}},
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data ProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	kc := authn.NewMultiKeychain(google.Keychain, authn.RefreshingKeychain(authn.DefaultKeychain, 30*time.Minute))
	ropts := []remote.Option{
		remote.WithAuthFromKeychain(kc),
		remote.WithUserAgent("terraform-provider-cosign/" + p.version),
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

	attestationEntryType := "intoto"
	if !data.DefaultAttestationEntryType.IsNull() && !data.DefaultAttestationEntryType.IsUnknown() {
		attestationEntryType = data.DefaultAttestationEntryType.ValueString()
	}

	opts := &ProviderOpts{
		ropts:                       ropts,
		keychain:                    kc,
		oidc:                        &oidcProvider{},
		defaultAttestationEntryType: attestationEntryType,
		signers:                     map[string]*fulcio.SignerVerifier{},
		rekorClients:                map[string]*client.Rekor{},
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

// EntryTypeValidator is a string validator that checks that the string is a valid Rekor entry type.
type EntryTypeValidator struct{}

var _ validator.String = EntryTypeValidator{}

func (v EntryTypeValidator) Description(context.Context) string {
	return "value must be one of (`dsse`, `intoto`)"
}

func (v EntryTypeValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v EntryTypeValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()

	switch val {
	case "dsse", "intoto":
		return
	default:
		resp.Diagnostics.AddError("error validating default_attestation_entry_type", v.Description(ctx))
	}
}
