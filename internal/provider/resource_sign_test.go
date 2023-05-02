package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	ocitesting "github.com/chainguard-dev/terraform-provider-oci/testing"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccResourceCosignSign(t *testing.T) {
	if _, ok := os.LookupEnv("ACTIONS_ID_TOKEN_REQUEST_URL"); !ok {
		t.Skip("Unable to keylessly sign without an actions token")
	}

	repo, cleanup := ocitesting.SetupRepository(t, "test")
	defer cleanup()

	// Push two images by digest.
	img1, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	dig1, err := img1.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref1 := repo.Digest(dig1.String())
	if err := remote.Write(ref1, img1); err != nil {
		t.Fatal(err)
	}

	img2, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	dig2, err := img2.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref2 := repo.Digest(dig2.String())
	if err := remote.Write(ref2, img2); err != nil {
		t.Fatal(err)
	}

	img3, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	dig3, err := img3.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref3 := repo.Digest(dig3.String())
	if err := remote.Write(ref3, img3); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Sign and verify the first image.
			{
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
`, ref1, ref1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"cosign_sign.foo", "image", regexp.MustCompile("^"+ref1.String())),
					resource.TestMatchResourceAttr(
						"cosign_sign.foo", "signed_ref", regexp.MustCompile("^"+ref1.String())),
					// Check that it got signed!
					resource.TestMatchResourceAttr(
						"data.cosign_verify.bar", "verified_ref", regexp.MustCompile("^"+ref1.String())),
				),
			},

			// Update the sign resource to sign the second image, and verify that.
			{
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
`, ref2, ref2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"cosign_sign.foo", "image", regexp.MustCompile("^"+ref2.String())),
					resource.TestMatchResourceAttr(
						"cosign_sign.foo", "signed_ref", regexp.MustCompile("^"+ref2.String())),
					// Check that it got signed!
					resource.TestMatchResourceAttr(
						"data.cosign_verify.bar", "verified_ref", regexp.MustCompile("^"+ref2.String())),
				),
			},
		},
	})
}
