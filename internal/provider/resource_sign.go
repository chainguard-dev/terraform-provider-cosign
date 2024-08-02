package provider

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant"
	"github.com/chainguard-dev/terraform-provider-oci/pkg/validators"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

var (
	_ resource.Resource                = &SignResource{}
	_ resource.ResourceWithImportState = &SignResource{}
)

func NewSignResource() resource.Resource {
	return &SignResource{}
}

type SignResource struct {
	popts *ProviderOpts
}

type SignResourceModel struct {
	Id        types.String `tfsdk:"id"`
	Image     types.String `tfsdk:"image"`
	Conflict  types.String `tfsdk:"conflict"`
	SignedRef types.String `tfsdk:"signed_ref"`
	FulcioURL types.String `tfsdk:"fulcio_url"`
	RekorURL  types.String `tfsdk:"rekor_url"`
}

func (r *SignResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sign"
}

func (r *SignResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This signs the provided image digest with cosign.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The immutable digest this resource signs.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"image": schema.StringAttribute{
				MarkdownDescription: "The digest of the container image to sign.",
				Optional:            false,
				Required:            true,
				Validators:          []validator.String{validators.DigestValidator{}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"conflict": schema.StringAttribute{
				MarkdownDescription: "How to handle conflicting signature values",
				Computed:            true,
				Optional:            true,
				Required:            false,
				Default:             stringdefault.StaticString("APPEND"),
				Validators:          []validator.String{ConflictValidator{}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"signed_ref": schema.StringAttribute{
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
	}
}

func (r *SignResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SignResource) doSign(ctx context.Context, data *SignResourceModel) (string, error, error) {
	digest, err := name.NewDigest(data.Image.ValueString())
	if err != nil {
		return "", nil, errors.New("Unable to parse image digest")
	}

	if os.Getenv("TF_COSIGN_DISABLE") != "" {
		return digest.String(), errors.New("TF_COSIGN_DISABLE is set, skipping signing"), nil
	}
	if !r.popts.oidc.Enabled(ctx) {
		return digest.String(), errors.New("no ambient credentials are available to sign with, skipping signing"), nil
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

	// TODO: This should probably be configurable?
	var annotations map[string]interface{} = nil

	if err := secant.Sign(ctx, data.Conflict.ValueString(), annotations, sv, rekorClient, []name.Digest{digest}, r.popts.ropts); err != nil {
		return "", nil, fmt.Errorf("unable to sign image %q: %w", digest.String(), err)
	}
	return digest.String(), nil, nil
}

func (r *SignResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *SignResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, warning, err := r.doSign(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("error while signing", err.Error())
		return
	} else if warning != nil {
		resp.Diagnostics.AddWarning("warning while signing", warning.Error())
	}

	data.Id = types.StringValue(digest)
	data.SignedRef = types.StringValue(digest)

	tflog.Trace(ctx, "created a resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SignResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *SignResourceModel
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
	data.SignedRef = types.StringValue(digest.String())

	// TODO(mattmoor): should we check that the signature didn't disappear?

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SignResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *SignResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, warning, err := r.doSign(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("error while signing", err.Error())
		return
	} else if warning != nil {
		resp.Diagnostics.AddWarning("warning while signing", warning.Error())
	}

	data.Id = types.StringValue(digest)
	data.SignedRef = types.StringValue(digest)

	tflog.Trace(ctx, "updated a resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SignResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *SignResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: If we ever want to delete the image from the registry, we can do it here.
}

func (r *SignResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
