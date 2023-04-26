package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/providers"
)

var _ resource.Resource = &SignResource{}
var _ resource.ResourceWithImportState = &SignResource{}

func NewSignResource() resource.Resource {
	return &SignResource{}
}

type SignResource struct {
}

type SignResourceModel struct {
	Id        types.String `tfsdk:"id"`
	Image     types.String `tfsdk:"image"`
	SignedRef types.String `tfsdk:"signed_ref"`
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
				Validators:          []validator.String{digestValidator{}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"signed_ref": schema.StringAttribute{
				MarkdownDescription: "This always matches the input digest, but is a convenience for composition.",
				Computed:            true,
			},
		},
	}
}

func (r *SignResource) Configure(context.Context, resource.ConfigureRequest, *resource.ConfigureResponse) {
}

func doSign(ctx context.Context, data *SignResourceModel) (string, error, error) {
	digest, err := name.NewDigest(data.Image.ValueString())
	if err != nil {
		return "", nil, errors.New("Unable to parse image digest")
	}

	if !providers.Enabled(ctx) {
		return digest.String(), errors.New("no ambient credentials are available to sign with, skipping signing."), nil
	}

	// TODO(mattmoor): Move these to be configuration options.
	const (
		fulcioURL = "https://fulcio.sigstore.dev"
		rekorURL  = "https://rekor.sigstore.dev"
	)

	ropts := &options.RootOptions{
		Timeout: options.DefaultTimeout,
	}
	kopts := options.KeyOpts{
		FulcioURL:        fulcioURL,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	sopts := options.SignOptions{
		SkipConfirmation: true,
		Fulcio: options.FulcioOptions{
			URL: fulcioURL,
		},
		Rekor: options.RekorOptions{
			URL: rekorURL,
		},
		Recursive:  true,
		Upload:     true,
		TlogUpload: true,
		Registry: options.RegistryOptions{
			KubernetesKeychain: true,
		},
	}

	if err := sign.SignCmd(ropts, kopts, sopts, []string{digest.String()}); err != nil {
		return "", nil, fmt.Errorf("Unable to sign image: %w", err)
	}
	return digest.String(), nil, nil
}

func (r *SignResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *SignResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, warning, err := doSign(ctx, data)
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

	digest, warning, err := doSign(ctx, data)
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
