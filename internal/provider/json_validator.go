package provider

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type jsonValidator struct{}

var _ validator.String = jsonValidator{}

func (v jsonValidator) Description(context.Context) string             { return "value must be valid json" }
func (v jsonValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v jsonValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()

	var untyped interface{}
	if err := json.Unmarshal([]byte(val), &untyped); err != nil {
		resp.Diagnostics.AddError("Invalid json", err.Error())
	}
}
