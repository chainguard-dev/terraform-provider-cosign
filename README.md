# Terraform Provider for [`cosign`](https://github.com/sigstore/cosign)

🚨 **This is a work in progress.** 🚨

https://registry.terraform.io/providers/chainguard-dev/cosign

## Usage

This provides a `cosign_verify` data source, which can be used with any
containerized infrastructure rules to enforce deploy-time policy checking:

```hcl
data "cosign_verify" "example" {
  image  = "cgr.dev/chainguard/static:latest-glibc"
  policy = file("my-policy.yaml")
}

# Use "data.cosign_verify.example.verified_ref" in downstream rules (see below).
```


This provider also exposes `cosign_sign` and `cosign_attest` resources that will
sign and attest a provided OCI digest, which is intended to compose with
OCI providers such as [`ko`](https://github.com/ko-build/terraform-provider-ko),
[`apko`](https://github.com/chainguard-dev/terraform-provider-apko), and
[`oci`](https://github.com/chainguard-dev/terraform-provider-oci).

Here is an example using the `ko` provider building on the verified base image
above:

```hcl
# This is simply for illustration purposes!
resource "ko_build" "image-build" {
  base_image  = data.cosign_verify.example.verified_ref
  importpath  = "..."
  repo        = var.where-to-publish
}

resource "cosign_sign" "example" {
  image = ko_build.image-build.image_ref
}

resource "cosign_attest" "example" {
  image          = cosign_sign.example.signed_ref
  predicate_type = "https://example.com/my/predicate/type"
  predicate      = jsonencode({
    // Your claim here!
  })
}

# Reference cosign_attest.example.attested_ref to ensure we wait for all of the
# metadata to be published.
```
