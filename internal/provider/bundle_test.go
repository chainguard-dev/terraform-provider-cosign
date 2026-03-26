package provider

import (
	"bytes"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestParsePredicateType(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"custom", "https://cosign.sigstore.dev/attestation/v1", false},
		{"slsaprovenance", "https://slsa.dev/provenance/v0.2", false},
		{"spdx", "https://spdx.dev/Document", false},
		{"spdxjson", "https://spdx.dev/Document", false},
		{"cyclonedx", "https://cyclonedx.org/bom", false},
		{"link", "https://in-toto.io/Link/v1", false},
		{"vuln", "https://cosign.sigstore.dev/attestation/vuln/v1", false},
		// Full URIs are passed through.
		{"https://example.com/my-predicate/v1", "https://example.com/my-predicate/v1", false},
		// Invalid values.
		{"notavalidtype", "", true},
		{"", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parsePredicateType(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got none", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
				return
			}
			if got != tc.want {
				t.Errorf("parsePredicateType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNewAttestStatement(t *testing.T) {
	digest, err := name.NewDigest("example.com/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	predicate := bytes.NewBufferString(`{"buildType": "test"}`)
	stmt, err := newAttestStatement(digest, predicate, "https://slsa.dev/provenance/v0.2")
	if err != nil {
		t.Fatal(err)
	}

	if stmt.Digest.String() != digest.String() {
		t.Errorf("digest = %q, want %q", stmt.Digest.String(), digest.String())
	}
	if stmt.Type != "https://slsa.dev/provenance/v0.2" {
		t.Errorf("type = %q, want %q", stmt.Type, "https://slsa.dev/provenance/v0.2")
	}
	if len(stmt.Payload) == 0 {
		t.Error("expected non-empty payload")
	}
}
