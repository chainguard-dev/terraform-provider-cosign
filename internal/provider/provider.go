package provider

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant"
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
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/fulcio/pkg/api"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// Environment variable that, when set, skips attesting/signing altogether
// and silences any associated warnings.
const tfCosignDisableEnvVar = "TF_COSIGN_DISABLE"

// Valid values for signature_format.
const (
	signatureFormatLegacy = "legacy"
	signatureFormatBundle = "bundle"
	signatureFormatBoth   = "both"
)

// Default Sigstore public-good endpoints. With these, the bundle path loads
// its endpoints from the TUF-configured SigningConfig. Any other value makes
// it sign against the given Fulcio and Rekor v1 instead (see
// bundleSigningConfig).
const (
	defaultFulcioURL = "https://fulcio.sigstore.dev"
	defaultRekorURL  = "https://rekor.sigstore.dev"
)

// validateBundleURLs reports an error if signature_format includes bundle,
// use_rekor_v2 is set and fulcio_url or rekor_url is set to a non-default
// value: use_rekor_v2 loads its endpoints from TUF, so the overrides would
// silently do nothing.
func validateBundleURLs(sigFmt, fulcioURL, rekorURL string, useRekorV2 bool) error {
	if !shouldPerformBundle(sigFmt) || !useRekorV2 {
		return nil
	}
	if !isDefaultEndpoints(fulcioURL, rekorURL) {
		return fmt.Errorf("fulcio_url and rekor_url must be unset or %q and %q when signature_format is %q or %q and use_rekor_v2 is set (it uses TUF-configured endpoints)", defaultFulcioURL, defaultRekorURL, signatureFormatBundle, signatureFormatBoth)
	}
	return nil
}

func isDefaultEndpoints(fulcioURL, rekorURL string) bool {
	return (fulcioURL == "" || fulcioURL == defaultFulcioURL) && (rekorURL == "" || rekorURL == defaultRekorURL)
}

// bundleSigningConfig returns a SigningConfig that signs against the given
// Fulcio (API v1) and Rekor (API v1) instances, without a timestamp
// authority: Rekor v1 entries carry an integrated time, which is what
// verification checks the short-lived certificate against.
func bundleSigningConfig(fulcioURL, rekorURL string) (*root.SigningConfig, error) {
	return root.NewSigningConfig(root.SigningConfigMediaType02,
		[]root.Service{{URL: fulcioURL, MajorAPIVersion: 1}},
		nil,
		[]root.Service{{URL: rekorURL, MajorAPIVersion: 1}},
		root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
		nil,
		root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
	)
}

// Ensure Provider satisfies various provider interfaces.
var _ provider.Provider = &Provider{}

type Provider struct {
	version string
}

// ProviderModel describes the provider data model.
type ProviderModel struct {
	DefaultAttestationEntryType types.String `tfsdk:"default_attestation_entry_type"`
	DefaultSignatureFormat      types.String `tfsdk:"default_signature_format"`
	Timeout                     types.String `tfsdk:"timeout"`
	UseRekorV2                  types.Bool   `tfsdk:"use_rekor_v2"`
}

type ProviderOpts struct {
	ropts                       []remote.Option
	keychain                    authn.Keychain
	defaultAttestationEntryType string
	defaultSignatureFormat      string
	timeout                     time.Duration
	useRekorV2                  bool

	oidc fulcio.OIDCProvider

	sync.Mutex

	// Keyed off fulcio URL.
	signers map[string]*fulcio.SignerVerifier

	// Keyed off rekor URL.
	rekorClients map[string]*client.Rekor

	// Lazily initialized bundle signers for the "bundle" signing path, keyed
	// off fulcio and rekor URL. Cached at the provider level so that the
	// ephemeral keypair and Fulcio cert are generated at most once per
	// instance across all sign/attest resource operations.
	bundleSigners map[bundleEndpoints]*secant.BundleSigner
}

type bundleEndpoints struct {
	fulcioURL, rekorURL string
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

func (p *ProviderOpts) getBundleSigner(fulcioURL, rekorURL string) (*secant.BundleSigner, error) {
	p.Lock()
	defer p.Unlock()

	key := bundleEndpoints{fulcioURL, rekorURL}
	if bs, ok := p.bundleSigners[key]; ok {
		return bs, nil
	}

	// Sign against non-default endpoints with a SigningConfig built from
	// them. When use_rekor_v2 is set, drive the bundle path at a Rekor v2
	// instance by loading the Rekor v2 SigningConfig from TUF. Either is fed
	// through the WithSigningConfig seam instead of the default config.
	var opts []secant.BundleSignerOption
	switch {
	case !isDefaultEndpoints(fulcioURL, rekorURL):
		sc, err := bundleSigningConfig(fulcioURL, rekorURL)
		if err != nil {
			return nil, fmt.Errorf("building signing config: %w", err)
		}
		opts = append(opts, secant.WithSigningConfig(sc))
	case p.useRekorV2:
		sc, err := cosign.SigningConfigRekorV2()
		if err != nil {
			return nil, fmt.Errorf("loading rekor v2 signing config: %w", err)
		}
		opts = append(opts, secant.WithSigningConfig(sc))
	}
	bs, err := secant.NewBundleSigner(p.oidc, opts...)
	if err != nil {
		return nil, err
	}

	p.bundleSigners[key] = bs
	return bs, nil
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
			"default_signature_format": schema.StringAttribute{
				MarkdownDescription: fmt.Sprintf("Default signature format to use for signing. Valid values are '%s' (default), '%s', or '%s'. Can be overridden per-resource.",
					signatureFormatLegacy, signatureFormatBundle, signatureFormatBoth),
				Optional:   true,
				Validators: []validator.String{SignatureFormatValidator{}},
			},
			"timeout": schema.StringAttribute{
				MarkdownDescription: "Timeout for signing and attestation operations, as a Go duration string (e.g. '5m', '10m'). Defaults to '3m'.",
				Optional:            true,
				Validators:          []validator.String{DurationValidator{}},
			},
			"use_rekor_v2": schema.BoolAttribute{
				MarkdownDescription: fmt.Sprintf("When true, the bundle signing path targets Rekor v2 by loading the Rekor v2 SigningConfig from TUF instead of the default. Only affects '%s' and '%s' signing; ignored for '%s'. Cannot be combined with a non-default fulcio_url or rekor_url on a resource.",
					signatureFormatBundle, signatureFormatBoth, signatureFormatLegacy),
				Optional: true,
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

	defaultSignatureFormat := signatureFormatLegacy
	if !data.DefaultSignatureFormat.IsNull() && !data.DefaultSignatureFormat.IsUnknown() {
		defaultSignatureFormat = data.DefaultSignatureFormat.ValueString()
	}

	timeout := options.DefaultTimeout
	if !data.Timeout.IsNull() && !data.Timeout.IsUnknown() {
		d, err := time.ParseDuration(data.Timeout.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid timeout", "Unable to parse timeout duration: "+err.Error())
			return
		}
		timeout = d
	}

	useRekorV2 := false
	if !data.UseRekorV2.IsNull() && !data.UseRekorV2.IsUnknown() {
		useRekorV2 = data.UseRekorV2.ValueBool()
	}

	opts := &ProviderOpts{
		ropts:                       ropts,
		keychain:                    kc,
		oidc:                        &oidcProvider{},
		defaultAttestationEntryType: attestationEntryType,
		defaultSignatureFormat:      defaultSignatureFormat,
		timeout:                     timeout,
		useRekorV2:                  useRekorV2,
		signers:                     map[string]*fulcio.SignerVerifier{},
		rekorClients:                map[string]*client.Rekor{},
		bundleSigners:               map[bundleEndpoints]*secant.BundleSigner{},
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

// SignatureFormatValidator is a string validator that checks that the string is a valid signature format.
type SignatureFormatValidator struct{}

var _ validator.String = SignatureFormatValidator{}

func (v SignatureFormatValidator) Description(context.Context) string {
	return fmt.Sprintf("value must be one of (`%s`, `%s`, `%s`)", signatureFormatLegacy, signatureFormatBundle, signatureFormatBoth)
}

func (v SignatureFormatValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v SignatureFormatValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()

	switch val {
	case signatureFormatLegacy, signatureFormatBundle, signatureFormatBoth:
		return
	default:
		resp.Diagnostics.AddError("error validating signature_format", v.Description(ctx))
	}
}

func shouldPerformLegacy(signatureFormat string) bool {
	return slices.Contains([]string{signatureFormatLegacy, signatureFormatBoth}, signatureFormat)
}

func shouldPerformBundle(signatureFormat string) bool {
	return slices.Contains([]string{signatureFormatBundle, signatureFormatBoth}, signatureFormat)
}

// DurationValidator is a string validator that checks that the string is a valid Go duration.
type DurationValidator struct{}

var _ validator.String = DurationValidator{}

func (v DurationValidator) Description(context.Context) string {
	return "value must be a valid Go duration string (e.g. '5m', '10m', '1h30m')"
}

func (v DurationValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v DurationValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := time.ParseDuration(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddError("error validating timeout", err.Error())
	}
}
