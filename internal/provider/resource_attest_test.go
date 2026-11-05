package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	ocitesting "github.com/chainguard-dev/terraform-provider-oci/testing"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccResourceCosignAttest(t *testing.T) {
	keyless := testKeyless(t)

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
		// Attestations persist in the registry after destroy (by design).
		CheckDestroy: func(*terraform.State) error { return nil },
		Steps: []resource.TestStep{
			// Attest and verify the first image.
			{
				ConfigVariables: keyless,
				Config: keylessVariables + fmt.Sprintf(`
resource "cosign_attest" "foo" {
  fulcio_url = var.fulcio_url
  rekor_url  = var.rekor_url
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
          url = var.fulcio_url
          identities = [{
            issuer  = var.issuer
            subject = var.subject
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
          url = var.rekor_url
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

			// Verify import works for the attest resource.
			// Predicate fields and computed defaults cannot be reconstructed from import.
			{
				ConfigVariables:         keyless,
				ResourceName:            "cosign_attest.foo",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"predicate_type", "predicate", "predicate_file", "predicates", "conflict", "fulcio_url", "rekor_url"},
			},

			// Update the resource to attest the second image (this time via a file!), and verify it.
			{
				ConfigVariables: keyless,
				Config: keylessVariables + fmt.Sprintf(`
resource "cosign_attest" "foo" {
  fulcio_url = var.fulcio_url
  rekor_url  = var.rekor_url
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
          url = var.fulcio_url
          identities = [{
            issuer  = var.issuer
            subject = var.subject
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
          url = var.rekor_url
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

	attRef := ref1.Tag(strings.ReplaceAll(dig1.String(), ":", "-") + ".att")

	att, err := remote.Image(attRef)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := countAttestations(t, att), 1; got != want {
		t.Errorf("got %d attestation layers, want %d", got, want)
	}

	url2 := "https://example.com/" + uuid.New().String()

	prevDigest, err := att.Digest()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		conflict  string
		wantCount int
		entryType string
		noop      bool
	}{{
		conflict:  "APPEND",
		entryType: "intoto",
		wantCount: 3,
	}, {
		conflict:  "REPLACE",
		entryType: "intoto",
		wantCount: 2,
	}, {
		conflict:  "SKIPSAME",
		entryType: "intoto",
		wantCount: 2,
		noop:      true,
	}, {
		conflict:  "SKIPSAME",
		entryType: "dsse",
		wantCount: 2,
		noop:      true,
	}, {
		conflict:  "REPLACE",
		entryType: "dsse",
		wantCount: 2,
	}} {
		t.Run(fmt.Sprintf("%s_%s", tc.conflict, tc.entryType), func(t *testing.T) {
			// Now we also attest using the multiple predicates form.
			// One of the predicates is the same predicateType as above.
			// The second predicate has a new predicateType.
			//
			// Depending on the conflict type, we expect to see different behavior:
			// - APPEND will just append the 2 predicates, resulting in 3 total.
			// - REPLACE will replace by predicate and elminate the duplicates, dropping it down to 2.
			// - SKIPSAME will see that the statements are the same as what we added in REPLACE, and we will remain at 2.
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					// Attest and verify the first image.
					{
						ConfigVariables: keyless,
						Config: keylessVariables + fmt.Sprintf(`

provider "cosign" {
  default_attestation_entry_type = %q
}

resource "cosign_attest" "foo" {
  fulcio_url = var.fulcio_url
  rekor_url  = var.rekor_url
  image          = %q
  conflict       = %q
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
          url = var.fulcio_url
          identities = [{
            issuer  = var.issuer
            subject = var.subject
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
          url = var.rekor_url
        }
      }]
    }
  })
}
`, tc.entryType, ref1, tc.conflict, url, value, url2, tmp.Name(), hash, ref1, url, url, value, url2, url2, value),
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

			att, err := remote.Image(attRef)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := countAttestations(t, att), tc.wantCount; got != want {
				t.Errorf("got %d attestation layers, want %d", got, want)
			}

			nextDigest, err := att.Digest()
			if err != nil {
				t.Fatal(err)
			}

			if tc.noop {
				if prevDigest != nextDigest {
					t.Errorf("expected noop, but attestation was updated")
				}
			} else {
				if prevDigest == nextDigest {
					t.Errorf("expected attestation to change, but saw noop")
				}
			}

			prevDigest = nextDigest
		})
	}
}

func countAttestations(t *testing.T, att v1.Image) int {
	t.Helper()

	layers, err := att.Layers()
	if err != nil {
		t.Fatal(err)
	}

	return len(layers)
}

// TestAccResourceCosignAttestBundle attests in the formats that write a
// bundle, and verifies each kind of attestation the format writes.
func TestAccResourceCosignAttestBundle(t *testing.T) {
	keyless := testKeyless(t)

	repo, cleanup := ocitesting.SetupRepository(t, "test")
	defer cleanup()

	for _, tc := range []struct {
		format string
		verify []string
	}{{
		format: signatureFormatBundle,
		verify: []string{signatureFormatBundle},
	}, {
		format: signatureFormatBoth,
		verify: []string{signatureFormatLegacy, signatureFormatBundle},
	}} {
		t.Run(tc.format, func(t *testing.T) {
			img, err := random.Image(1024, 1)
			if err != nil {
				t.Fatal(err)
			}
			dig, err := img.Digest()
			if err != nil {
				t.Fatal(err)
			}
			ref := repo.Digest(dig.String())
			if err := remote.Write(ref, img); err != nil {
				t.Fatal(err)
			}

			url := "https://example.com/" + uuid.New().String()
			value := uuid.New().String()

			// One verify per kind of attestation, as a policy admits an image
			// that satisfies any one of its authorities.
			config := keylessVariables + fmt.Sprintf(`
resource "cosign_attest" "foo" {
  fulcio_url       = var.fulcio_url
  rekor_url        = var.rekor_url
  image            = %q
  signature_format = %q
  predicates {
    type = %q
    json = jsonencode({
      foo = %q
    })
  }
}
`, ref, tc.format, url, value)
			var checks []resource.TestCheckFunc
			for _, format := range tc.verify {
				config += fmt.Sprintf(`
data "cosign_verify" %q {
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
        signatureFormat = %q
        keyless = {
          url = var.fulcio_url
          identities = [{
            issuer  = var.issuer
            subject = var.subject
          }]
        }
        attestations = [{
          name = "must-have-attestation"
          predicateType = %q
          policy = {
            type = "cue"
            data = <<EOF
              predicateType: %q
              predicate: {
                foo: %q
              }
            EOF
          }
        }]
        ctlog = {
          url = var.rekor_url
        }
      }]
    }
  })
}
`, format, ref, format, url, url, value)
				checks = append(checks, resource.TestMatchResourceAttr(
					"data.cosign_verify."+format, "verified_ref", regexp.MustCompile("^"+ref.String())))
			}

			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				// Attestations persist in the registry after destroy (by design).
				CheckDestroy: func(*terraform.State) error { return nil },
				Steps: []resource.TestStep{{
					ConfigVariables: keyless,
					Config:          config,
					Check:           resource.ComposeTestCheckFunc(checks...),
				}},
			})
		})
	}
}
