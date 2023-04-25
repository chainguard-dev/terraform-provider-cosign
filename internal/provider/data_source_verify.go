package provider

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/policy-controller/pkg/policy"
)

func dataSourceCosignVerify() *schema.Resource {
	return &schema.Resource{
		Description: "This verifies the provided image against the specified policy.",

		ReadContext: dataSourceCosignVerifyRead,

		Schema: map[string]*schema.Schema{
			"image": {
				Description: "The image tag or digest of the container image to verify.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				ValidateDiagFunc: func(data interface{}, _ cty.Path) diag.Diagnostics {
					raw, ok := data.(string)
					if !ok {
						return diag.Errorf("%v is a %T, wanted a string", data, data)
					}
					_, err := name.ParseReference(raw)
					return diag.FromErr(err)
				},
			},
			"policy": {
				Description: "The sigstore policy-controller policy to verify the image against.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				ValidateDiagFunc: func(data interface{}, _ cty.Path) diag.Diagnostics {
					raw, ok := data.(string)
					if !ok {
						return diag.Errorf("%v is a %T, wanted a string", data, data)
					}
					wc := warningCollector{}
					if _, err := buildVerifier(context.Background(), raw, wc.Write); err != nil {
						return diag.FromErr(err)
					}
					return nil
				},
			},
			"verified_ref": {
				Description: "This contains the digest of the image that was verified against the provided policy.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

type warningCollector diag.Diagnostics

func (wc *warningCollector) Write(s string, i ...interface{}) {
	*wc = append(*wc, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  fmt.Sprintf(s, i...),
	})
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

func dataSourceCosignVerifyRead(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	ref, err := name.ParseReference(d.Get("image").(string))
	if err != nil {
		return diag.FromErr(err)
	}

	digest, err := ociremote.ResolveDigest(ref)
	if err != nil {
		return diag.FromErr(err)
	}

	wc := warningCollector{}
	vfy, err := buildVerifier(ctx, d.Get("policy").(string), wc.Write)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := vfy.Verify(ctx, digest, authn.DefaultKeychain); err != nil {
		return diag.FromErr(err)
	}

	d.Set("verified_ref", digest.String())
	d.SetId(digest.String())

	// Return any diagnostics the warning collector accumulated.
	return diag.Diagnostics(wc)
}
