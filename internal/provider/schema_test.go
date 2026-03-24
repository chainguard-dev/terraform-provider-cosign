package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestSignResourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rs := NewSignResource()
	resp := &resource.SchemaResponse{}
	rs.Schema(ctx, resource.SchemaRequest{}, resp)
	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema validation failed: %s", diags.Errors())
	}
}

func TestAttestResourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rs := NewAttestResource()
	resp := &resource.SchemaResponse{}
	rs.Schema(ctx, resource.SchemaRequest{}, resp)
	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema validation failed: %s", diags.Errors())
	}
}

func TestCopyResourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rs := NewCopyResource()
	resp := &resource.SchemaResponse{}
	rs.Schema(ctx, resource.SchemaRequest{}, resp)
	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema validation failed: %s", diags.Errors())
	}
}

func TestVerifyDataSourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ds := NewVerifyDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(ctx, datasource.SchemaRequest{}, resp)
	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("schema validation failed: %s", diags.Errors())
	}
}
