package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestShouldPerformLegacy(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{signingFormatModeLegacy, true},
		{signingFormatModeCurrent, false},
		{signingFormatModeBoth, true},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := shouldPerformLegacy(tc.mode); got != tc.want {
				t.Errorf("shouldPerformLegacy(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

func TestShouldPerformCurrent(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{signingFormatModeLegacy, false},
		{signingFormatModeCurrent, true},
		{signingFormatModeBoth, true},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := shouldPerformCurrent(tc.mode); got != tc.want {
				t.Errorf("shouldPerformCurrent(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

func TestSigningFormatModeValidator(t *testing.T) {
	ctx := context.Background()
	v := SigningFormatModeValidator{}

	tests := []struct {
		name    string
		value   types.String
		wantErr bool
	}{
		{"legacy", types.StringValue("legacy"), false},
		{"current", types.StringValue("current"), false},
		{"both", types.StringValue("both"), false},
		{"invalid", types.StringValue("invalid"), true},
		{"null", types.StringNull(), false},
		{"unknown", types.StringUnknown(), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := validator.StringRequest{
				ConfigValue: tc.value,
			}
			resp := &validator.StringResponse{}
			v.ValidateString(ctx, req, resp)
			if tc.wantErr && !resp.Diagnostics.HasError() {
				t.Errorf("expected error for %q, got none", tc.name)
			}
			if !tc.wantErr && resp.Diagnostics.HasError() {
				t.Errorf("unexpected error for %q: %s", tc.name, resp.Diagnostics.Errors())
			}
		})
	}
}

func TestSigningFormatModeDescription(t *testing.T) {
	v := SigningFormatModeValidator{}
	desc := v.Description(context.Background())
	if desc == "" {
		t.Error("expected non-empty description")
	}
	mdDesc := v.MarkdownDescription(context.Background())
	if mdDesc != desc {
		t.Errorf("MarkdownDescription() = %q, want %q", mdDesc, desc)
	}
}
