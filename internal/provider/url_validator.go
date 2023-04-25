package provider

import (
	"context"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type urlValidator struct{}

var _ validator.String = urlValidator{}

func (v urlValidator) Description(context.Context) string             { return "value must be a valid URL" }
func (v urlValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v urlValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if _, err := url.Parse(val); err != nil {
		resp.Diagnostics.AddError("Invalid url", err.Error())
	}
}
