resource "cosign_sign" "example" {
  image = ko_build.image-build.image_ref
}