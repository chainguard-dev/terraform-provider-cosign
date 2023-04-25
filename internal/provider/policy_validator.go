package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/sigstore/policy-controller/pkg/policy"
)

type policyValidator struct{}

var _ validator.String = policyValidator{}

func (v policyValidator) Description(context.Context) string             { return "value must be a valid OCI ref" }
func (v policyValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v policyValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	raw := req.ConfigValue.ValueString()
	wc := warningCollector{resp.Diagnostics}
	if _, err := buildVerifier(ctx, raw, wc.Write); err != nil {
		resp.Diagnostics.AddError("Invalid policy", err.Error())
	}
}

type warningCollector struct {
	diags diag.Diagnostics
}

func (wc *warningCollector) Write(s string, i ...interface{}) {
	wc.diags.AddWarning("Warning", fmt.Sprintf(s, i...))
}

func buildVerifier(ctx context.Context, body string, ww policy.WarningWriter) (policy.Verifier, error) {
	vfy, err := policy.Compile(ctx, policy.Verification{
		NoMatchPolicy: "deny",
		Policies: &[]policy.Source{{
			Data: body,
		}},
	}, ww)
	if err != nil {
		return nil, err
	}
	return vfy, nil
}
