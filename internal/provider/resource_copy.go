package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/chainguard-dev/terraform-provider-oci/pkg/validators"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/copy"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

var (
	_ resource.Resource                = &CopyResource{}
	_ resource.ResourceWithImportState = &CopyResource{}
)

func NewCopyResource() resource.Resource {
	return &CopyResource{}
}

type CopyResource struct {
}

type CopyResourceModel struct {
	Id          types.String `tfsdk:"id"`
	Source      types.String `tfsdk:"source"`
	Destination types.String `tfsdk:"destination"`

	CopiedRef types.String `tfsdk:"copied_ref"`
}

func (r *CopyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_copy"
}

func (r *CopyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This copies the provided image digest cosign copy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The immutable digest this resource copies, along with its signatures, etc.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"source": schema.StringAttribute{
				MarkdownDescription: "The digest of the container image to copy.",
				Optional:            false,
				Required:            true,
				Validators:          []validator.String{validators.DigestValidator{}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"destination": schema.StringAttribute{
				MarkdownDescription: "The destination repository.",
				Optional:            false,
				Required:            true,
				Validators:          []validator.String{validators.RepoValidator{}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"copied_ref": schema.StringAttribute{
				MarkdownDescription: "This always matches the input digest, but is a convenience for composition.",
				Computed:            true,
			},
		},
	}
}

func (r *CopyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
}

func doCopy(ctx context.Context, data *CopyResourceModel) (string, error) {
	digest, err := name.NewDigest(data.Source.ValueString())
	if err != nil {
		return "", errors.New("Unable to parse image digest")
	}

	ropts := options.RegistryOptions{
		KubernetesKeychain: true,
	}
	dst, err := name.NewRepository(data.Destination.ValueString())
	if err != nil {
		return "", errors.New("Unable to parse destination repository")
	}

	if err := copy.CopyCmd(ctx, ropts, digest.String(), dst.String(), false, false); err != nil {
		return "", fmt.Errorf("Unable to copy image: %w", err)
	}
	return dst.Digest(digest.DigestStr()).String(), nil
}

func (r *CopyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *CopyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, err := doCopy(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("error while Copying", err.Error())
		return
	}

	data.Id = types.StringValue(digest)
	data.CopiedRef = types.StringValue(digest)

	tflog.Trace(ctx, "created a resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CopyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *CopyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, err := name.NewDigest(data.Source.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to parse image digest: %v", err))
		return
	}
	data.Id = types.StringValue(digest.String())
	data.CopiedRef = types.StringValue(digest.String())

	// TODO(mattmoor): should we check that the Copyature didn't disappear?

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CopyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *CopyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	digest, err := doCopy(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("error while Copying", err.Error())
		return
	}

	data.Id = types.StringValue(digest)
	data.CopiedRef = types.StringValue(digest)

	tflog.Trace(ctx, "updated a resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CopyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *CopyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: If we ever want to delete the image from the registry, we can do it here.
}

func (r *CopyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
