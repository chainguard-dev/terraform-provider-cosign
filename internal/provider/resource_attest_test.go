package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"testing"

	ocitesting "github.com/chainguard-dev/terraform-provider-oci/testing"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccResourceCosignAttest(t *testing.T) {
	if _, ok := os.LookupEnv("ACTIONS_ID_TOKEN_REQUEST_URL"); !ok {
		t.Skip("Unable to keylessly attest without an actions token")
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

	url := "https://example.com/" + uuid.New().String()

	value := uuid.New().String()

	tmp, err := os.CreateTemp("", "cosign-attest-*.json")
	if err != nil {
		t.Fatal(err)
	}
	contents := fmt.Sprintf(`{"foo": %q}`, value)
	if _, err := tmp.WriteString(contents); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	rawHash := sha256.Sum256([]byte(contents))
	hash := hex.EncodeToString(rawHash[:])

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Attest and verify the first image.
			{
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
`, ref1, url, value, ref1, url, url, value),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"cosign_attest.foo", "image", regexp.MustCompile("^"+ref1.String())),
					resource.TestMatchResourceAttr(
						"cosign_attest.foo", "attested_ref", regexp.MustCompile("^"+ref1.String())),
					// Check that it got attested!
					resource.TestMatchResourceAttr(
						"data.cosign_verify.bar", "verified_ref", regexp.MustCompile("^"+ref1.String())),
				),
			},

			// Update the resource to attest the second image (this time via a file!), and verify it.
			{
				Config: fmt.Sprintf(`
resource "cosign_attest" "foo" {
  image          = %q
  predicate_type = %q
  predicate_file {
    path   = %q
    sha256 = %q
  }
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
`, ref2, url, tmp.Name(), hash, ref2, url, url, value),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"cosign_attest.foo", "image", regexp.MustCompile("^"+ref2.String())),
					resource.TestMatchResourceAttr(
						"cosign_attest.foo", "attested_ref", regexp.MustCompile("^"+ref2.String())),
					// Check that it got attested!
					resource.TestMatchResourceAttr(
						"data.cosign_verify.bar", "verified_ref", regexp.MustCompile("^"+ref2.String())),
				),
			},
		},
	})
}

func TestAccResourceCosignAttests(t *testing.T) {
	if _, ok := os.LookupEnv("ACTIONS_ID_TOKEN_REQUEST_URL"); !ok {
		t.Skip("Unable to keylessly attest without an actions token")
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

	url := "https://example.com/" + uuid.New().String()
	url2 := "https://example.com/" + uuid.New().String()

	value := uuid.New().String()

	tmp, err := os.CreateTemp("", "cosign-attest-*.json")
	if err != nil {
		t.Fatal(err)
	}
	contents := fmt.Sprintf(`{"foo": %q}`, value)
	if _, err := tmp.WriteString(contents); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	rawHash := sha256.Sum256([]byte(contents))
	hash := hex.EncodeToString(rawHash[:])

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Attest and verify the first image.
			{
				Config: fmt.Sprintf(`
resource "cosign_attest" "foo" {
  image          = %q
  predicates {
    type = %q
    json = jsonencode({
      foo = %q
    })
  }

  predicates {
    type = %q
    file {
      path   = %q
      sha256 = %q
    }
  }
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
        },{
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
`, ref1, url, value, url2, tmp.Name(), hash, ref1, url, url, value, url2, url2, value),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"cosign_attest.foo", "image", regexp.MustCompile("^"+ref1.String())),
					resource.TestMatchResourceAttr(
						"cosign_attest.foo", "attested_ref", regexp.MustCompile("^"+ref1.String())),
					// Check that it got attested!
					resource.TestMatchResourceAttr(
						"data.cosign_verify.bar", "verified_ref", regexp.MustCompile("^"+ref1.String())),
				),
			},
		},
	})
}
