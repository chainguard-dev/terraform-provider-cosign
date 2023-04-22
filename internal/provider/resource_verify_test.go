package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceCosignVerify(t *testing.T) {
	repo := "cgr.dev/chainguard/static"

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "cosign_verify" "foo" {
  image  = %q
  policy = jsonencode({
    apiVersion = "policy.sigstore.dev/v1beta1"
    kind       = "ClusterImagePolicy"
    metadata = {
      name = "chainguard-images-are-signed"
    }
    spec = {
      images = [{
        glob = "cgr.dev/chainguard/**"
      }]
      authorities = [{
        keyless = {
          url = "https://fulcio.sigstore.dev"
          identities = [{
            issuer  = "https://token.actions.githubusercontent.com"
            subject = "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main"
          }]
        }
        ctlog = {
          url = "https://rekor.sigstore.dev"
        }
      }]
    }
  })
}`, repo),
			Check: resource.ComposeTestCheckFunc(
				resource.TestMatchResourceAttr(
					"cosign_verify.foo", "image", regexp.MustCompile("^"+repo)),
				resource.TestMatchResourceAttr(
					"cosign_verify.foo", "verified_ref", regexp.MustCompile("^"+repo+"@sha256:")),
			),
		}},
	})

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "cosign_verify" "foo" {
  image  = %q
  policy = jsonencode({
    apiVersion = "policy.sigstore.dev/v1beta1"
    kind       = "ClusterImagePolicy"
    metadata = {
      name = "chainguard-images-are-signed"
    }
    spec = {
      images = [{
        glob = "cgr.dev/chainguard/**"
      }]
      authorities = [{
        static = {
          action = "fail"
        }
      }]
    }
  })
}`, repo),
			ExpectError: regexp.MustCompile("disallowed by static policy"),
		}},
	})
}
