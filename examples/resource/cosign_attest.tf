resource "cosign_attest" "example" {
  image = cosign_sign.example.signed_ref

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