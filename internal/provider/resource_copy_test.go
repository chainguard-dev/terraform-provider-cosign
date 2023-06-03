package provider

import (
	"fmt"
	"os"
	"testing"

	ocitesting "github.com/chainguard-dev/terraform-provider-oci/testing"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccResourceCosignCopy(t *testing.T) {
	if _, ok := os.LookupEnv("ACTIONS_ID_TOKEN_REQUEST_URL"); !ok {
		t.Skip("Unable to keylessly sign without an actions token")
	}

	src, cleanup := ocitesting.SetupRepository(t, "src")
	defer cleanup()

	dst, cleanup := ocitesting.SetupRepository(t, "dst")
	defer cleanup()

	// Push an image by digest to the source repo.
	img1, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	dig1, err := img1.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref1 := src.Digest(dig1.String())
	if err := remote.Write(ref1, img1); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// Sign and copy the image, then verify the copy's signature.
			Config: fmt.Sprintf(`
resource "cosign_sign" "foo" {
  image = %q
}

resource "cosign_attest" "foo" {
  image          = %q
  predicate_type = "https://predicate.type"
  predicate      = jsonencode({
    foo = "bar"
  })
}

resource "cosign_copy" "copy" {
  source      = cosign_sign.foo.signed_ref
  destination = %q
}

data "cosign_verify" "copy" {
  image  = cosign_copy.copy.copied_ref
  policy = jsonencode({
    apiVersion = "policy.sigstore.dev/v1beta1"
    kind       = "ClusterImagePolicy"
    metadata = {
      name = "attested-and-signed-it"
    }
    spec = {
      images = [{
        glob = cosign_copy.copy.copied_ref
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
          predicateType = "https://predicate.type"
          policy = {
            type = "cue"
            // When we do things in this style, we can use file("foo.cue") too!
            data = <<EOF
              predicateType: "https://predicate.type"
              predicate: {
                foo: "bar"
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
`, ref1, ref1, dst),
			Check: resource.ComposeTestCheckFunc(
				// Check that it got signed!
				resource.TestCheckResourceAttr(
					"data.cosign_verify.copy", "verified_ref", dst.Digest(dig1.String()).String(),
				),
			),
		}},
	})
}
