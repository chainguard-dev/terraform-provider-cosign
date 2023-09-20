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

See provider examples:

- [ECS](./provider-examples/ecs/README.md)


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

  predicates {
    type = "https://example.com/my/predicate/type"
    json = jsonencode({
      // Your claim here!
    })
  }

  // Inlining e.g. huge SBOMs will slow down terraform a lot, so reference a file.
  predicates {
    type = "https://example.com/my/predicate/too-big-for-terraform.tfstate"
    file = {
      path   = "/tmp/giant-file.json"
      sha256 = "74af7407b59f9021f76a6f9ee66149c5df1ef6442617a805a7860ce18074158d"
    }
  }
}

# Reference cosign_attest.example.attested_ref to ensure we wait for all of the
# metadata to be published.
```

## Disabling

The provider will skip signing/attesting when ambient credentials are not
present, but can also be explicitly disabled by setting `TF_COSIGN_DISABLE` to
any value.
