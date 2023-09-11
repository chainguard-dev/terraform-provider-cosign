package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/chainguard-dev/terraform-provider-cosign/internal/secant"
	"github.com/chainguard-dev/terraform-provider-oci/pkg/validators"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

var (
	_ resource.Resource                = &AttestResource{}
	_ resource.ResourceWithImportState = &AttestResource{}
)

func NewAttestResource() resource.Resource {
	return &AttestResource{}
}

type AttestResource struct {
	FulcioURL types.String
	RekorURL  types.String

	popts *ProviderOpts
}

type AttestResourceModel struct {
	Id            types.String `tfsdk:"id"`
	Image         types.String `tfsdk:"image"`
	PredicateType types.String `tfsdk:"predicate_type"`
	Predicate     types.String `tfsdk:"predicate"`
	PredicateFile types.List   `tfsdk:"predicate_file"`

	AttestedRef types.String `tfsdk:"attested_ref"`
	FulcioURL   types.String `tfsdk:"fulcio_url"`
	RekorURL    types.String `tfsdk:"rekor_url"`
}

func (r *AttestResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_attest"
}

func (r *AttestResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	singlePredicate := stringvalidator.ExactlyOneOf(
		path.MatchRoot("predicate"),
		path.MatchRoot("predicate_file").AtListIndex(0).AtName("sha256"),
	)

	resp.Schema = schema.Schema{
		MarkdownDescription: "This attests the provided image digest with cosign.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The immutable digest this resource attests.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"image": schema.StringAttribute{
				MarkdownDescription: "The digest of the container image to attest.",
				Optional:            false,
				Required:            true,
				Validators:          []validator.String{validators.DigestValidator{}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"predicate_type": schema.StringAttribute{
				MarkdownDescription: "The in-toto predicate type of the claim being attested.",
				Optional:            false,
				Required:            true,
				Validators:          []validator.String{validators.URLValidator{}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"predicate": schema.StringAttribute{
				MarkdownDescription: "The JSON body of the in-toto predicate's claim.",
				Optional:            true,
				Required:            false,
				Validators: []validator.String{
					validators.JSONValidator{},
					singlePredicate,
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"attested_ref": schema.StringAttribute{
				MarkdownDescription: "This always matches the input digest, but is a convenience for composition.",
				Computed:            true,
			},
			"fulcio_url": schema.StringAttribute{
				MarkdownDescription: "Address of sigstore PKI server (default https://fulcio.sigstore.dev).",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("https://fulcio.sigstore.dev"),
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"rekor_url": schema.StringAttribute{
				MarkdownDescription: "Address of rekor transparency log server (default https://rekor.sigstore.dev).",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("https://rekor.sigstore.dev"),
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
		Blocks: map[string]schema.Block{
			"predicate_file": schema.ListNestedBlock{
				MarkdownDescription: "The path and sha256 hex of the predicate to attest.",
				Validators:          []validator.List{listvalidator.SizeBetween(1, 1)},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"sha256": schema.StringAttribute{
							MarkdownDescription: "The sha256 hex hash of the predicate body.",
							Optional:            true,
							Required:            false,
							Validators: []validator.String{
								singlePredicate,
								stringvalidator.AlsoRequires(path.MatchRoot("predicate_file").AtListIndex(0).AtName("path")),
							},
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
						"path": schema.StringAttribute{
							MarkdownDescription: "The path to a file containing the predicate to attest.",
							Optional:            true,
							Required:            false,
							Validators: []validator.String{
								stringvalidator.AlsoRequires(path.MatchRoot("predicate_file").AtListIndex(0).AtName("sha256")),
							},
						},
					},
				},
			},
		},
	}
}

func (r *AttestResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	popts, ok := req.ProviderData.(*ProviderOpts)
	if !ok || popts == nil {
		resp.Diagnostics.AddError("Client Error", "invalid provider data")
		return
	}
	r.popts = popts
}

func (r *AttestResource) doAttest(ctx context.Context, data *AttestResourceModel) (string, error, error) {
	digest, err := name.NewDigest(data.Image.ValueString())
	if err != nil {
		return "", nil, errors.New("unable to parse image digest")
	}

	if os.Getenv("TF_COSIGN_DISABLE") != "" {
		return digest.String(), errors.New("TF_COSIGN_DISABLE is set, skipping attesting"), nil
	}
	if !r.popts.oidc.Enabled(ctx) {
		return digest.String(), errors.New("no ambient credentials are available to attest with, skipping attesting"), nil
	}

	// Write the attestation to a temporary file.
	var path string
	switch {
	// Write the predicate to a file to pass to attest.
	case data.Predicate.ValueString() != "":
		file, err := os.CreateTemp("", "")
		if err != nil {
			return "", nil, err
		}
		defer os.Remove(file.Name())
		if _, err := file.WriteString(data.Predicate.ValueString()); err != nil {
			return "", nil, err
		}
		if err := file.Close(); err != nil {
			return "", nil, err
		}
		path = file.Name()

	case len(data.PredicateFile.Elements()) > 0:
		attrs := data.PredicateFile.Elements()[0].(basetypes.ObjectValue).Attributes()
		path = attrs["path"].(basetypes.StringValue).ValueString()
		expectedHash := attrs["sha256"].(basetypes.StringValue).ValueString()

		contents, err := os.ReadFile(path)
		if err != nil {
			return "", nil, err
		}
		rawHash := sha256.Sum256(contents)
		if got, want := hex.EncodeToString(rawHash[:]), expectedHash; got != want {
			return "", nil, fmt.Errorf("sha256(%q) = %s, expected %s", path, got, want)
		}

	default:
		return "", nil, errors.New("one of predicate or predicate_file must be specified")
	}

	predicate, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("open %q: %w", path, err)
	}

	stmt, err := secant.NewStatement(digest, predicate, data.PredicateType.ValueString())
	if err != nil {
		return "", nil, fmt.Errorf("creating attestation statement: %w", err)
	}

	sv, err := r.popts.signerVerifier(data.FulcioURL.ValueString())
	if err != nil {
		return "", nil, fmt.Errorf("creating signer: %w", err)
	}

	rekorClient, err := r.popts.rekorClient(data.RekorURL.ValueString())
	if err != nil {
		return "", nil, fmt.Errorf("creating rekor client: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, options.DefaultTimeout)
	defer cancel()

	if err := secant.Attest(ctx, stmt, sv, rekorClient, r.popts.ropts); err != nil {
		return "", nil, fmt.Errorf("unable to sign image: %w", err)
	}

	return digest.String(), nil, nil
}

func (r *AttestResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *AttestResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, warning, err := r.doAttest(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("error while attesting", err.Error())
		return
	} else if warning != nil {
		resp.Diagnostics.AddWarning("warning while attesting", warning.Error())
	}

	data.Id = types.StringValue(digest)
	data.AttestedRef = types.StringValue(digest)

	tflog.Trace(ctx, "created a resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AttestResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *AttestResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, err := name.NewDigest(data.Image.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to parse image digest: %v", err))
		return
	}
	data.Id = types.StringValue(digest.String())
	data.AttestedRef = types.StringValue(digest.String())

	// TODO(mattmoor): should we check that the signature didn't disappear?

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AttestResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *AttestResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, warning, err := r.doAttest(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("error while attesting", err.Error())
		return
	} else if warning != nil {
		resp.Diagnostics.AddWarning("warning while attesting", warning.Error())
	}

	data.Id = types.StringValue(digest)
	data.AttestedRef = types.StringValue(digest)

	tflog.Trace(ctx, "updated a resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AttestResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *AttestResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: If we ever want to delete the image from the registry, we can do it here.
}

func (r *AttestResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
