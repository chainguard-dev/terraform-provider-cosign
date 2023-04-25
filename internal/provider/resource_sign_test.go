package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceCosignSign(t *testing.T) {
	digest := os.Getenv("TEST_IMAGE")

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "cosign_sign" "foo" {
  image = %q
}

data "cosign_verify" "bar" {
  image  = cosign_sign.foo.signed_ref
  policy = jsonencode({
    apiVersion = "policy.sigstore.dev/v1beta1"
    kind       = "ClusterImagePolicy"
    metadata = {
      name = "signed-it"
    }
    spec = {
      images = [{
        glob = %q
      }]
      authorities = [{
        keyless = {
          url = "https://fulcio.sigstore.dev"
          identities = [{
            issuer  = "https://token.actions.githubusercontent.com"
            subject = "https://github.com/chainguard-dev/terraform-provider-cosign/.github/workflows/test.yml@refs/heads/main"
          }]
        }
        ctlog = {
          url = "https://rekor.sigstore.dev"
        }
      }]
    }
  })
}
`, digest, digest),
			Check: resource.ComposeTestCheckFunc(
				resource.TestMatchResourceAttr(
					"cosign_sign.foo", "image", regexp.MustCompile("^"+digest)),
				resource.TestMatchResourceAttr(
					"cosign_sign.foo", "signed_ref", regexp.MustCompile("^"+digest)),
				// Check that it got signed!
				resource.TestMatchResourceAttr(
					"data.cosign_verify.bar", "verified_ref", regexp.MustCompile("^"+digest)),
			),
		}},
	})
}
