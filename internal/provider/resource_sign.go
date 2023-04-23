package provider

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/providers"
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

	if !providers.Enabled(ctx) {
		return diag.Errorf("no ambient credentials are available to sign with.")
	}

	// TODO(mattmoor): Move these to be configuration options.
	const (
		fulcioURL = "https://fulcio.sigstore.dev"
		rekorURL  = "https://rekor.sigstore.dev"
	)

	ropts := &options.RootOptions{
		Timeout: options.DefaultTimeout,
	}
	kopts := options.KeyOpts{
		FulcioURL:        fulcioURL,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	sopts := options.SignOptions{
		SkipConfirmation: true,
		Fulcio: options.FulcioOptions{
			URL: fulcioURL,
		},
		Rekor: options.RekorOptions{
			URL: rekorURL,
		},
		Recursive:  true,
		Upload:     true,
		TlogUpload: true,
		Registry: options.RegistryOptions{
			KubernetesKeychain: true,
		},
	}

	if err := sign.SignCmd(ropts, kopts, sopts, []string{digest.String()}); err != nil {
		return diag.FromErr(err)
	}

	d.Set("signed_ref", digest.String())
	d.SetId(digest.String())
	return nil
}

func resourceCosignSignRead(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	digest, err := name.NewDigest(d.Get("image").(string))
	if err != nil {
		return diag.FromErr(err)
	}

	// TODO(mattmoor): should we check that the signature didn't disappear?

	d.Set("signed_ref", digest.String())
	d.SetId(digest.String())
	return nil
}

func resourceCosignSignDelete(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// TODO: If we ever want to delete the image from the registry, we can do it here.
	return nil
}
