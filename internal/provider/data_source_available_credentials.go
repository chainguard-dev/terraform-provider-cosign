package provider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"

	_ "github.com/chainguard-dev/terraform-provider-cosign/internal/provider/interactive"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/providers/filesystem"
	_ "github.com/sigstore/cosign/v2/pkg/providers/github"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &AvailableDataSource{}

func NewAvailableDataSource() datasource.DataSource {
	return &AvailableDataSource{}
}

// ExampleDataSource defines the data source implementation.
type AvailableDataSource struct {
	popts *ProviderOpts
}

// ExampleDataSourceModel describes the data source data model.
type AvailableDataSourceModel struct {
	Id        types.String `tfsdk:"id"`
	Available types.Set    `tfsdk:"available"`
}

func (d *AvailableDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_available_credentials"
}

func (d *AvailableDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This produces a list of available keyless signing credentials.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "This contains the hash of available keyless signing credentials.",
				Computed:            true,
			},
			"available": schema.SetAttribute{
				MarkdownDescription: "This contains the names of available keyless signing credentials.",
				Computed:            true,
				ElementType:         basetypes.StringType{},
			},
		},
	}
}

func (d *AvailableDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	popts, ok := req.ProviderData.(*ProviderOpts)
	if !ok || popts == nil {
		resp.Diagnostics.AddError("Client Error", "invalid provider data")
		return
	}
	d.popts = popts
}

// Copied from "github.com/sigstore/cosign/v2/pkg/providers/filesystem"
func gitHubAvailable() bool {
	if env.Getenv(env.VariableGitHubRequestToken) == "" {
		return false
	}
	if env.Getenv(env.VariableGitHubRequestURL) == "" {
		return false
	}
	return true
}

// Allow this path to be overridden for testing.
var filesystemTokenPath = filesystem.FilesystemTokenPath

// Copied from "github.com/sigstore/cosign/v2/pkg/providers/filesystem"
func filesystemAvailable() bool {
	// If we can stat the file without error then this is enabled.
	_, err := os.Stat(filesystemTokenPath)
	return err == nil
}

func interactiveAvailable() bool {
	return os.Getenv("TF_COSIGN_LOCAL") != ""
}

func (d *AvailableDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AvailableDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var available []string
	if interactiveAvailable() {
		available = append(available, "interactive")
	}
	if filesystemAvailable() {
		available = append(available, "filesystem")
	}
	if gitHubAvailable() {
		available = append(available, "github-actions")
	}
	sort.Strings(available)

	h := sha256.New()
	for _, a := range available {
		fmt.Fprintln(h, a)
	}
	digest := fmt.Sprintf("%x", h.Sum(nil))

	var diag diag.Diagnostics
	data.Available, diag = types.SetValueFrom(ctx, basetypes.StringType{}, available)
	if diag.HasError() {
		resp.Diagnostics.Append(diag...)
		return
	}

	data.Id = types.StringValue(digest)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
