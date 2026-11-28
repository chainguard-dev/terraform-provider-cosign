package provider

import (
	"context"
	"slices"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
)

// TestRegistryOptionsAreNotShared checks that concurrent resources each get
// their own copy of the shared registry options. cosign_copy hands them to
// cosign, which appends remote.WithContext(ctx) per call. If the slice had a
// spare slot, both calls would write into the same backing array and one
// resource would run on the other's context.
func TestRegistryOptionsAreNotShared(t *testing.T) {
	ropts, err := registryOptions(authn.DefaultKeychain, "test")
	if err != nil {
		t.Fatalf("registryOptions() = %v", err)
	}
	if len(ropts) != cap(ropts) {
		t.Fatalf("len(ropts) = %d, cap(ropts) = %d, want them equal", len(ropts), cap(ropts))
	}

	ro := options.RegistryOptions{RegistryClientOpts: ropts}
	a := ro.GetRegistryClientOpts(context.Background())
	b := ro.GetRegistryClientOpts(context.Background())
	if &a[0] == &b[0] {
		t.Error("two GetRegistryClientOpts calls share a backing array")
	}
}

// TestKeychainUsesCredentialHelpers checks that the provider's keychain falls
// back to the ambient credential helpers when the Docker config has no
// credentials for a registry, as cosign's Kubernetes keychain did.
func TestKeychainUsesCredentialHelpers(t *testing.T) {
	// An empty Docker config, so only the credential helpers can answer.
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_TOKEN", "hunter2")

	for _, tc := range []struct {
		registry string
		want     authn.AuthConfig
	}{{
		registry: "ghcr.io",
		want:     authn.AuthConfig{Username: "octocat", Password: "hunter2"},
	}, {
		registry: "registry.example.com",
		want:     authn.AuthConfig{},
	}} {
		t.Run(tc.registry, func(t *testing.T) {
			reg, err := name.NewRegistry(tc.registry)
			if err != nil {
				t.Fatalf("name.NewRegistry() = %v", err)
			}
			auth, err := keychain().Resolve(reg)
			if err != nil {
				t.Fatalf("Resolve() = %v", err)
			}
			got, err := auth.Authorization()
			if err != nil {
				t.Fatalf("Authorization() = %v", err)
			}
			if *got != tc.want {
				t.Errorf("Authorization() = %+v, want %+v", *got, tc.want)
			}
		})
	}
}

// recordingHelper is an authn.Helper that records the registries it is asked
// about and answers each with a refresh token.
type recordingHelper struct{ asked []string }

func (h *recordingHelper) Get(serverURL string) (string, string, error) {
	h.asked = append(h.asked, serverURL)
	return "<token>", "refresh-token", nil
}

// TestAzureHelperOnlyAsksForACRHosts checks that the Azure ACR credential
// helper is only asked about ACR hosts and mcr.microsoft.com. Its own check
// also accepts hosts such as evil.azurecr.io.attacker.com and would send them
// the ambient Azure AD token (GO-2026-6225).
func TestAzureHelperOnlyAsksForACRHosts(t *testing.T) {
	for _, tc := range []struct {
		registry string
		allowed  bool
	}{{
		registry: "myregistry.azurecr.io",
		allowed:  true,
	}, {
		registry: "myregistry.azurecr.us",
		allowed:  true,
	}, {
		registry: "myregistry.azurecr.io:443",
		allowed:  true,
	}, {
		registry: "mcr.microsoft.com",
		allowed:  true,
	}, {
		registry: "evil.azurecr.io.attacker.com",
		allowed:  false,
	}, {
		registry: "evilazurecr.io",
		allowed:  false,
	}, {
		registry: "ghcr.io",
		allowed:  false,
	}} {
		t.Run(tc.registry, func(t *testing.T) {
			reg, err := name.NewRegistry(tc.registry)
			if err != nil {
				t.Fatalf("name.NewRegistry() = %v", err)
			}
			h := &recordingHelper{}
			auth, err := authn.NewKeychainFromHelper(azureHelper{h}).Resolve(reg)
			if err != nil {
				t.Fatalf("Resolve() = %v", err)
			}
			got, err := auth.Authorization()
			if err != nil {
				t.Fatalf("Authorization() = %v", err)
			}

			var want authn.AuthConfig
			var wantAsked []string
			if tc.allowed {
				want = authn.AuthConfig{Username: "<token>", IdentityToken: "refresh-token"}
				wantAsked = []string{tc.registry}
			}
			if *got != want {
				t.Errorf("Authorization() = %+v, want %+v", *got, want)
			}
			if !slices.Equal(h.asked, wantAsked) {
				t.Errorf("helper asked about %q, want %q", h.asked, wantAsked)
			}
		})
	}
}
