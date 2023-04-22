# Terraform Provider for [`cosign`](https://github.com/sigstore/cosign)

🚨 **This is a work in progress.** 🚨

https://registry.terraform.io/providers/mattmoor/cosign

## Usage

This provides an `cosign_sign` and `cosign_verify` resources that will sign and
verify the provided images with `cosign`.

```hcl
provider "cosign" {}

# Verify the Chainguard base image against a policy from
# github.com/sigstore/policy-controller.
resource "cosign_verify" "example" {
  image  = "cgr.dev/chainguard/static:latest-glibc"

  # This can also be inlined or fetched from a URL using the "http" data source
  # check out https://github.com/chainguard-dev/policy-catalog for examples!
  policy = file("my-policy.yaml")
}

# This is simply for illustration purposes!
# see: https://github.com/ko-build/terraform-provider-ko
resource "ko_build" "image-build" {
  base_image  = cosign_verify.example.verified_ref
  importpath  = "..."
  repo        = var.where-to-public
}

# Sign the produced image!
resource "cosign_sign" "example" {
  image = ko_build.image-build.image_ref
}
```
