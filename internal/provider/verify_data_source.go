package provider

import (
	"context"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &VerifyDataSource{}

func NewVerifyDataSource() datasource.DataSource {
	return &VerifyDataSource{}
}

// ExampleDataSource defines the data source implementation.
type VerifyDataSource struct {
}

// ExampleDataSourceModel describes the data source data model.
type VerifyDataSourceModel struct {
	Id          types.String `tfsdk:"id"`
	Image       types.String `tfsdk:"image"`
	Policy      types.String `tfsdk:"policy"`
	VerifiedRef types.String `tfsdk:"verified_ref"`
}

func (d *VerifyDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_verify"
}

func (d *VerifyDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This verifies the provided image against the specified policy.",
		Attributes: map[string]schema.Attribute{
			"image": schema.StringAttribute{
				MarkdownDescription: "The image tag or digest of the container image to verify.",
				Required:            true,
				Validators:          []validator.String{refValidator{}},
			},
			"policy": schema.StringAttribute{
				MarkdownDescription: "The sigstore policy-controller policy to verify the image against.",
				Required:            true,
				Validators:          []validator.String{policyValidator{}},
			},
			"verified_ref": schema.StringAttribute{
				MarkdownDescription: "This contains the digest of the image that was verified against the provided policy.",
				Computed:            true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "This contains the digest of the image that was verified against the provided policy.",
				Computed:            true,
			},
		},
	}
}

func (d *VerifyDataSource) Configure(context.Context, datasource.ConfigureRequest, *datasource.ConfigureResponse) {
}

func (d *VerifyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data VerifyDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ref, err := name.ParseReference(data.Image.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid image reference", err.Error())
		return
	}
	digest, err := ociremote.ResolveDigest(ref) // TODO: with creds?
	if err != nil {
		resp.Diagnostics.AddError("Unable to resolve digest", err.Error())
		return
	}

	wc := warningCollector{resp.Diagnostics}
	vfy, err := buildVerifier(ctx, data.Policy.ValueString(), wc.Write)
	if err != nil {
		resp.Diagnostics.AddError("Unable to build verifier", err.Error())
		return
	}
	resp.Diagnostics.Append(wc.diags...)

	if err := vfy.Verify(ctx, digest, authn.DefaultKeychain); err != nil {
		resp.Diagnostics.AddError("Verification failed", err.Error())
		return
	}

	data.VerifiedRef = types.StringValue(digest.String())
	data.Id = types.StringValue(digest.String())

	tflog.Trace(ctx, "read a data source")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
