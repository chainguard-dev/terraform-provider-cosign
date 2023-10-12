data "cosign_verify" "example" {
  image  = "cgr.dev/chainguard/static:latest-glibc"
  policy = file("my-policy.yaml")
}