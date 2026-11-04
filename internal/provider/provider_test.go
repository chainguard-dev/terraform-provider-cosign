package provider

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/config"
	// policy-controller reads Fulcio's roots through this deprecated client.
	"github.com/sigstore/sigstore/pkg/tuf" //nolint:staticcheck
)

// TestMain points the TUF client cosign and policy-controller read Sigstore's
// keys through at the TUF repository of the instance the keyless tests sign
// against, when .chainguard/ci/keyless.yaml provides one.
func TestMain(m *testing.M) {
	if mirror := os.Getenv("TEST_TUF_MIRROR"); mirror != "" {
		root, err := os.ReadFile(os.Getenv("TEST_TUF_ROOT"))
		if err != nil {
			log.Fatalf("reading TEST_TUF_ROOT: %v", err)
		}
		if err := tuf.Initialize(context.Background(), mirror, root); err != nil {
			log.Fatalf("initializing TUF from %s: %v", mirror, err)
		}
	}
	os.Exit(m.Run())
}

// testAccProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"cosign": providerserver.NewProtocol6WithError(New("test")()),
}

func testAccPreCheck(t *testing.T) {
	// You can add code here to run prior to any test case execution, for example assertions
	// about the appropriate environment variables being set are common to see in a pre-check
	// function.
}

// keylessVariables declares the variables testKeyless returns values for.
// The keyless tests' configs start with it and refer to the Sigstore instance
// through them.
const keylessVariables = `
variable "fulcio_url" {}
variable "rekor_url" {}
variable "issuer" {}
variable "subject" {}
`

// testKeyless returns the Sigstore instance the keyless tests sign against
// and the identity they sign as, which .chainguard/ci/keyless.yaml sets up
// in the environment, or skips the test without one. The provider signs with
// the token in SIGSTORE_ID_TOKEN.
func testKeyless(t *testing.T) config.Variables {
	t.Helper()
	if os.Getenv("SIGSTORE_ID_TOKEN") == "" {
		t.Skip("Unable to keylessly sign without SIGSTORE_ID_TOKEN")
	}
	vars := config.Variables{}
	for name, env := range map[string]string{
		"fulcio_url": "TEST_FULCIO_URL",
		"rekor_url":  "TEST_REKOR_URL",
		"issuer":     "TEST_OIDC_ISSUER",
		"subject":    "TEST_OIDC_SUBJECT",
	} {
		v := os.Getenv(env)
		if v == "" {
			t.Fatalf("%s must be set alongside SIGSTORE_ID_TOKEN", env)
		}
		vars[name] = config.StringVariable(v)
	}
	return vars
}
