package fulcio

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v3/pkg/cosign"
)

func TestAddTrustedRootCTLogKeys(t *testing.T) {
	// A snapshot of the sigstore staging instance's trusted_root.json. Its
	// log2026-1.us-east4 CT log key is published only here, not as a
	// standalone ctfe*.pub TUF target, so it must be discoverable through
	// this path for SCT verification to succeed against that log.
	trustedRootJSON, err := os.ReadFile(filepath.Join("testdata", "sigstage_trusted_root.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	pubKeys := cosign.NewTrustedTransparencyLogPubKeys()
	if err := addTrustedRootCTLogKeys(&pubKeys, trustedRootJSON); err != nil {
		t.Fatalf("addTrustedRootCTLogKeys() = %v", err)
	}

	if got, want := len(pubKeys.Keys), 5; got != want {
		t.Errorf("len(pubKeys.Keys): got = %d, want = %d", got, want)
	}
	for _, logID := range []string{
		// log2026-1.us-east4.ctfe.sigstage.dev: absent from the ctfe*.pub targets.
		"1638fb664e48d34e2799bf37594c876ac68232850ee1fb939c5c9bb52c5ebc87",
		// log2026-1.ctfe.sigstage.dev: also published as the ctfe_2026_1.pub target.
		"3e607153746e1892e090b236b14976272f67b44d6f92ce6f77114ab722a0a6b6",
	} {
		if _, ok := pubKeys.Keys[logID]; !ok {
			t.Errorf("pubKeys.Keys missing log ID %q", logID)
		}
	}

	// Merging the same trusted root again must not duplicate keys: they are
	// indexed by log ID.
	if err := addTrustedRootCTLogKeys(&pubKeys, trustedRootJSON); err != nil {
		t.Fatalf("addTrustedRootCTLogKeys() second merge = %v", err)
	}
	if got, want := len(pubKeys.Keys), 5; got != want {
		t.Errorf("len(pubKeys.Keys) after re-merge: got = %d, want = %d", got, want)
	}
}

func TestAddTrustedRootCTLogKeysInvalidJSON(t *testing.T) {
	pubKeys := cosign.NewTrustedTransparencyLogPubKeys()
	if err := addTrustedRootCTLogKeys(&pubKeys, []byte("not json")); err == nil {
		t.Error("addTrustedRootCTLogKeys() = nil, want error")
	}
}
