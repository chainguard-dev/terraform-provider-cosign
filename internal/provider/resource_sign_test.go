package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceCosignSign(t *testing.T) {
	digest := os.Getenv("TEST_IMAGE")

	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "cosign_sign" "foo" {
  image = %q
}`, digest),
			Check: resource.ComposeTestCheckFunc(
				resource.TestMatchResourceAttr(
					"cosign_sign.foo", "image", regexp.MustCompile("^"+digest)),
				resource.TestMatchResourceAttr(
					"cosign_sign.foo", "signed_ref", regexp.MustCompile("^"+digest)),
			),
		}},
	})
}
