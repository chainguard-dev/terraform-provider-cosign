package provider

import (
	"context"
	"encoding/json"
	"net/url"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/providers"
)

func resourceCosignAttest() *schema.Resource {
	return &schema.Resource{
		Description: "This signs the provided image digest with cosign.",

		CreateContext: resourceCosignAttestCreate,
		ReadContext:   resourceCosignAttestRead,
		DeleteContext: resourceCosignAttestDelete,

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
			"predicate_type": {
				Description: "The in-toto predicate type of the claim being attested.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				ValidateDiagFunc: func(data interface{}, _ cty.Path) diag.Diagnostics {
					raw, ok := data.(string)
					if !ok {
						return diag.Errorf("%v is a %T, wanted a string", data, data)
					}
					_, err := url.Parse(raw)
					return diag.FromErr(err)
				},
			},
			"predicate": {
				Description: "The JSON body of the in-toto predicate's claim.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				ValidateDiagFunc: func(data interface{}, _ cty.Path) diag.Diagnostics {
					raw, ok := data.(string)
					if !ok {
						return diag.Errorf("%v is a %T, wanted a string", data, data)
					}
					var v interface{}
					return diag.FromErr(json.Unmarshal([]byte(raw), &v))
				},
			},
			"attested_ref": {
				Description: "This always matches the input digest, but is a convenience for composition.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceCosignAttestCreate(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	digest, err := name.NewDigest(d.Get("image").(string))
	if err != nil {
		return diag.FromErr(err)
	}

	if !providers.Enabled(ctx) {
		d.Set("attested_ref", digest.String())
		d.SetId(digest.String())
		return diag.Diagnostics{{
			Severity: diag.Warning,
			Summary:  "no ambient credentials are available to sign with, skipping signing.",
		}}
	}

	// TODO(mattmoor): Move these to be configuration options.
	const (
		fulcioURL = "https://fulcio.sigstore.dev"
		rekorURL  = "https://rekor.sigstore.dev"
	)

	// Write the attestation to a temporary file.
	file, err := os.CreateTemp("", "")
	if err != nil {
		return diag.FromErr(err)
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(d.Get("predicate").(string)); err != nil {
		return diag.FromErr(err)
	}
	if err := file.Close(); err != nil {
		diag.FromErr(err)
	}

	ac := attest.AttestCommand{
		KeyOpts: options.KeyOpts{
			FulcioURL:        fulcioURL,
			RekorURL:         rekorURL,
			SkipConfirmation: true,
		},
		RegistryOptions: options.RegistryOptions{
			KubernetesKeychain: true,
		},
		PredicatePath: file.Name(),
		PredicateType: d.Get("predicate_type").(string),
		Replace:       true,
		Timeout:       options.DefaultTimeout,
		TlogUpload:    true,
	}
	if err := ac.Exec(ctx, digest.String()); err != nil {
		return diag.FromErr(err)
	}

	d.Set("attested_ref", digest.String())
	d.SetId(digest.String())
	return nil
}

func resourceCosignAttestRead(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	digest, err := name.NewDigest(d.Get("image").(string))
	if err != nil {
		return diag.FromErr(err)
	}

	// TODO(mattmoor): should we check that the signature didn't disappear?

	d.Set("attested_ref", digest.String())
	d.SetId(digest.String())
	return nil
}

func resourceCosignAttestDelete(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// TODO: If we ever want to delete the image from the registry, we can do it here.
	return nil
}
