package provider

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCosignSign() *schema.Resource {
	return &schema.Resource{
		Description: "This signs the provided image digest with cosign.",

		CreateContext: resourceCosignSignCreate,
		ReadContext:   resourceCosignSignRead,
		DeleteContext: resourceCosignSignDelete,

		Schema: map[string]*schema.Schema{
			"image": {
				Description: "The digest of the container image to sign.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				ValidateDiagFunc: func(data interface{}, _ cty.Path) diag.Diagnostics {
					raw, ok := data.(string)
					if !ok {
						return diag.Errorf("%v is a %T, wanted a string", data, data)
					}
					_, err := name.NewDigest(raw)
					return diag.FromErr(err)
				},
			},
			"signed_ref": {
				Description: "This always matches the input digest, but is a convenience for composition.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceCosignSignCreate(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	digest, err := name.NewDigest(d.Get("image").(string))
	if err != nil {
		return diag.FromErr(err)
	}

	// TODO: Do something.

	d.Set("signed_ref", digest.String())
	d.SetId(digest.String())
	return nil
}

func resourceCosignSignRead(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	digest, err := name.NewDigest(d.Get("image").(string))
	if err != nil {
		return diag.FromErr(err)
	}

	// TODO: Do something.

	d.Set("signed_ref", digest.String())
	d.SetId(digest.String())
	return nil
}

func resourceCosignSignDelete(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// TODO: If we ever want to delete the image from the registry, we can do it here.
	return nil
}
