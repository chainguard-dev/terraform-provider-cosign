package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	ocitesting "github.com/chainguard-dev/terraform-provider-oci/testing"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
)

func TestAccResourceCosignSign(t *testing.T) {
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
		// Signatures persist in the registry after destroy (by design).
		CheckDestroy: func(*terraform.State) error { return nil },
		Steps: []resource.TestStep{
			// Sign and verify the first image.
			{
				ConfigVariables: keyless,
				Config: keylessVariables + fmt.Sprintf(`
resource "cosign_sign" "foo" {
  fulcio_url = var.fulcio_url
  rekor_url  = var.rekor_url
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
          url = var.fulcio_url
          identities = [{
            issuer  = var.issuer
            subject = var.subject
          }]
        }
        ctlog = {
          url = var.rekor_url
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

			// Verify import works for the sign resource.
			// conflict, fulcio_url, rekor_url cannot be reconstructed from import.
			{
				ConfigVariables:         keyless,
				ResourceName:            "cosign_sign.foo",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"conflict", "fulcio_url", "rekor_url"},
			},

			// Update the sign resource to sign the second image, and verify that.
			{
				ConfigVariables: keyless,
				Config: keylessVariables + fmt.Sprintf(`
resource "cosign_sign" "foo" {
  fulcio_url = var.fulcio_url
  rekor_url  = var.rekor_url
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
          url = var.fulcio_url
          identities = [{
            issuer  = var.issuer
            subject = var.subject
          }]
        }
        ctlog = {
          url = var.rekor_url
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

func TestAccResourceCosignSignConflict(t *testing.T) {
	keyless := testKeyless(t)

	repo, cleanup := ocitesting.SetupRepository(t, "test")
	defer cleanup()

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

	sigRef := ref1.Tag(strings.ReplaceAll(dig1.String(), ":", "-") + ".sig")
	prevDigest := v1.Hash{}

	for i, tc := range []struct {
		conflict  string
		wantCount int
		noop      bool
	}{{
		conflict:  "APPEND",
		wantCount: 1,
	}, {
		conflict:  "APPEND",
		wantCount: 2,
	}, {
		conflict:  "REPLACE",
		wantCount: 1,
	}, {
		conflict:  "SKIPSAME",
		wantCount: 1,
		noop:      true,
	}} {
		t.Run(fmt.Sprintf("%s (%d)", tc.conflict, i), func(t *testing.T) {
			// Depending on the conflict type, we expect to see different behavior:
			// - APPEND will just add a signature each time (we call it twice).
			// - REPLACE will replace by sig digest and elminate the duplicates, dropping it down to 1.
			// - SKIPSAME will see that the digests are the same as what we wrote in REPLACE and will be a noop.
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						ConfigVariables: keyless,
						Config: keylessVariables + fmt.Sprintf(`
		resource "cosign_sign" "foo" {
		  fulcio_url = var.fulcio_url
		  rekor_url  = var.rekor_url
  		image = %q

  		conflict = %q
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
          		url = var.fulcio_url
          		identities = [{
            		issuer  = var.issuer
            		subject = var.subject
          		}]
        		}
        		ctlog = {
          		url = var.rekor_url
        		}
      		}]
    		}
  		})
		}
		`, ref1, tc.conflict, ref1),
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
				},
			})

			sig, err := remote.Image(sigRef)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := countAttestations(t, sig), tc.wantCount; got != want {
				t.Errorf("got %d signature layers, want %d", got, want)
			}

			nextDigest, err := sig.Digest()
			if err != nil {
				t.Fatal(err)
			}

			if prevDigest != (v1.Hash{}) {
				if tc.noop {
					if prevDigest != nextDigest {
						t.Errorf("expected noop, but signature was updated")
					}
				} else {
					if prevDigest == nextDigest {
						t.Errorf("expected signature to change, but saw noop")
					}
				}
			}

			prevDigest = nextDigest
		})
	}
}

// TestAccResourceCosignSignBundle signs in the formats that write a bundle,
// and verifies each kind of signature the format writes.
func TestAccResourceCosignSignBundle(t *testing.T) {
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

			// One verify per kind of signature, as a policy admits an image
			// that satisfies any one of its authorities.
			config := keylessVariables + fmt.Sprintf(`
resource "cosign_sign" "foo" {
  fulcio_url       = var.fulcio_url
  rekor_url        = var.rekor_url
  image            = %q
  signature_format = %q
}
`, ref, tc.format)
			var checks []resource.TestCheckFunc
			for _, format := range tc.verify {
				// policy-controller verifies bundles only as attestations, so
				// check the bundle as one with the predicate type it signs.
				attestations := "[]"
				if format == signatureFormatBundle {
					attestations = fmt.Sprintf(`[{
          name          = "must-have-signature"
          predicateType = %q
        }]`, ctypes.CosignSignPredicateType)
				}
				config += fmt.Sprintf(`
data "cosign_verify" %q {
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
        signatureFormat = %q
        keyless = {
          url = var.fulcio_url
          identities = [{
            issuer  = var.issuer
            subject = var.subject
          }]
        }
        attestations = %s
        ctlog = {
          url = var.rekor_url
        }
      }]
    }
  })
}
`, format, ref, format, attestations)
				checks = append(checks, resource.TestMatchResourceAttr(
					"data.cosign_verify."+format, "verified_ref", regexp.MustCompile("^"+ref.String())))
			}

			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				// Signatures persist in the registry after destroy (by design).
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
