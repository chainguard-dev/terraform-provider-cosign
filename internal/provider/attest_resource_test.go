package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccResourceCosignAttest(t *testing.T) {
	digest := os.Getenv("TEST_IMAGE")

	url := "https://example.com/" + uuid.New().String()

	value := uuid.New().String()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "cosign_attest" "foo" {
  image          = %q
  predicate_type = %q
  predicate      = jsonencode({
    foo = %q
  })
}

data "cosign_verify" "bar" {
  image  = cosign_attest.foo.attested_ref
  policy = jsonencode({
    apiVersion = "policy.sigstore.dev/v1beta1"
    kind       = "ClusterImagePolicy"
    metadata = {
      name = "attested-it"
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
        attestations = [{
          name = "must-have-attestation"
          predicateType = %q
          policy = {
            type = "cue"
            // When we do things in this style, we can use file("foo.cue") too!
            data = <<EOF
              predicateType: %q
              predicate: {
                foo: string
                // Uncommenting this leads to a failure.
                // foo: "bar"
                foo: %q
              }
            EOF
          }
        }]
        ctlog = {
          url = "https://rekor.sigstore.dev"
        }
      }]
    }
  })
}
`, digest, url, value, digest, url, url, value),
			Check: resource.ComposeTestCheckFunc(
				resource.TestMatchResourceAttr(
					"cosign_attest.foo", "image", regexp.MustCompile("^"+digest)),
				resource.TestMatchResourceAttr(
					"cosign_attest.foo", "attested_ref", regexp.MustCompile("^"+digest)),
				// Check that it got attested!
				resource.TestMatchResourceAttr(
					"data.cosign_verify.bar", "verified_ref", regexp.MustCompile("^"+digest)),
			),
		}},
	})
}
