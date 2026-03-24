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
		{signatureFormatLegacy, true},
		{signatureFormatBundle, false},
		{signatureFormatBoth, true},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := shouldPerformLegacy(tc.mode); got != tc.want {
				t.Errorf("shouldPerformLegacy(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

func TestShouldPerformBundle(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{signatureFormatLegacy, false},
		{signatureFormatBundle, true},
		{signatureFormatBoth, true},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := shouldPerformBundle(tc.mode); got != tc.want {
				t.Errorf("shouldPerformBundle(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

func TestSignatureFormatValidator(t *testing.T) {
	ctx := context.Background()
	v := SignatureFormatValidator{}

	tests := []struct {
		name    string
		value   types.String
		wantErr bool
	}{
		{"legacy", types.StringValue("legacy"), false},
		{"bundle", types.StringValue("bundle"), false},
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

func TestSignatureFormatDescription(t *testing.T) {
	v := SignatureFormatValidator{}
	desc := v.Description(context.Background())
	if desc == "" {
		t.Error("expected non-empty description")
	}
	mdDesc := v.MarkdownDescription(context.Background())
	if mdDesc != desc {
		t.Errorf("MarkdownDescription() = %q, want %q", mdDesc, desc)
	}
}
