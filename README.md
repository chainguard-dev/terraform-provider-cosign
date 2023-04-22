# Terraform Provider for [`cosign`](https://github.com/sigstore/cosign)

🚨 **This is a work in progress.** 🚨

https://registry.terraform.io/providers/mattmoor/cosign

## Usage

This provides an `cosign_sign` resource that will sign the provided image digest
with `cosign`.

```hcl
provider "cosign" {}

resource "cosign_sign" "example" {
  image = "gcr.io/my-project/foo@sha256:deadbeef"
}
```
