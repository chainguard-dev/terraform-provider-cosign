terraform {
  required_providers {
    cosign = {
      source = "chainguard-dev/cosign"
    }
  }

  backend "inmem" {}

}

data "cosign_available_credentials" "available" {}

resource "cosign_sign" "image" {
  for_each      = data.cosign_available_credentials.available.available
  oidc_provider = each.key
  image         = "ttl.sh/jason@sha256:13b7e62e8df80264dbb747995705a986aa530415763a6c58f84a3ca8af9a5bcd"
}
