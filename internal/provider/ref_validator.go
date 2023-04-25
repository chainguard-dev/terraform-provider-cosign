package provider

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type refValidator struct{}

var _ validator.String = refValidator{}

func (v refValidator) Description(context.Context) string             { return "value must be a valid OCI ref" }
func (v refValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v refValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if _, err := name.ParseReference(val); err != nil {
		resp.Diagnostics.AddError("Invalid image reference", err.Error())
	}
}
