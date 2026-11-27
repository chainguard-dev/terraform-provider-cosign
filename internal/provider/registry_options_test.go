package provider

import (
	"context"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
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
