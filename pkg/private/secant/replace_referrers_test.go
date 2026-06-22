package secant

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/random"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	dsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"
)

// bundleWithDSSEPayload builds a minimal serialized sigstore bundle wrapping a
// DSSE envelope, enough for the SKIPSAME comparison to round-trip without a
// real signer.
func bundleWithDSSEPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	b := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &dsse.Envelope{
				Payload:     payload,
				PayloadType: "application/vnd.in-toto+json",
			},
		},
	}
	data, err := protojson.Marshal(b)
	if err != nil {
		t.Fatalf("marshaling bundle: %v", err)
	}
	return data
}

// TestMatchingBundleReferrers_ManifestSourced exercises the
// manifest-authoritative matching path. go-containerregistry's in-memory
// registry serves the native referrers API but builds index descriptors
// without the predicate-type annotation (a spec SHOULD); matching must fall
// back to the referrer manifest and still find both bundles.
func TestMatchingBundleReferrers_ManifestSourced(t *testing.T) {
	repo := setupTestRepo(t)

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	subject := pushImage(t, repo, img)

	// Two successive status writes for the same predicate type. Distinct
	// payloads give them distinct digests, mirroring two real referrers.
	if err := writeBundleReferrer(subject, []byte(`{"bundle":"one"}`), testPredicateType, nil, nil); err != nil {
		t.Fatalf("writing first referrer: %v", err)
	}
	if err := writeBundleReferrer(subject, []byte(`{"bundle":"two"}`), testPredicateType, nil, nil); err != nil {
		t.Fatalf("writing second referrer: %v", err)
	}

	opts := []ociremote.Option{ociremote.WithRemoteOptions()}

	matching, err := matchingBundleReferrers(subject, testPredicateType, opts, nil)
	if err != nil {
		t.Fatalf("matchingBundleReferrers: %v", err)
	}
	if len(matching) != 2 {
		t.Fatalf("expected 2 matching referrers, got %d", len(matching))
	}

	// A different predicate type must match neither.
	other, err := matchingBundleReferrers(subject, "https://example.com/other/v1", opts, nil)
	if err != nil {
		t.Fatalf("matchingBundleReferrers (other): %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("expected 0 matching referrers for unrelated predicate type, got %d", len(other))
	}

	// End-to-end REPLACE deletes every matching referrer (the caller then writes
	// the single replacement). Afterwards nothing matches.
	action, _, err := resolveBundleConflict(subject, testPredicateType, []byte(`{"bundle":"three"}`), Replace, nil, opts)
	if err != nil {
		t.Fatalf("resolveBundleConflict(Replace): %v", err)
	}
	if action != bundleWrite {
		t.Fatalf("expected REPLACE to request a write, got %v", action)
	}

	remaining, err := matchingBundleReferrers(subject, testPredicateType, opts, nil)
	if err != nil {
		t.Fatalf("matchingBundleReferrers after REPLACE: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected 0 matching referrers after REPLACE, got %d", len(remaining))
	}
}

// TestResolveBundleConflict_SkipSame confirms SKIPSAME skips an identical
// payload but writes a novel one, on a registry whose referrers index omits
// annotations.
func TestResolveBundleConflict_SkipSame(t *testing.T) {
	repo := setupTestRepo(t)

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	subject := pushImage(t, repo, img)

	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	if err := writeBundleReferrer(subject, bundleWithDSSEPayload(t, payload), testPredicateType, nil, nil); err != nil {
		t.Fatalf("writing referrer: %v", err)
	}

	opts := []ociremote.Option{ociremote.WithRemoteOptions()}

	// Identical payload: SKIPSAME must skip the write.
	action, _, err := resolveBundleConflict(subject, testPredicateType, payload, SkipSame, nil, opts)
	if err != nil {
		t.Fatalf("resolveBundleConflict(SkipSame, identical): %v", err)
	}
	if action != bundleSkip {
		t.Errorf("expected SKIPSAME to skip an identical payload, got %v", action)
	}

	// Different payload: SKIPSAME must request the write.
	action, _, err = resolveBundleConflict(subject, testPredicateType, []byte(`{"_type":"differs"}`), SkipSame, nil, opts)
	if err != nil {
		t.Fatalf("resolveBundleConflict(SkipSame, different): %v", err)
	}
	if action != bundleWrite {
		t.Errorf("expected SKIPSAME to write a novel payload, got %v", action)
	}
}

// TestResolveBundleConflict_RePushSame confirms REPUSHSAME re-pushes an existing
// identical payload (returning its referrer digest) but writes a novel one.
func TestResolveBundleConflict_RePushSame(t *testing.T) {
	repo := setupTestRepo(t)

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	subject := pushImage(t, repo, img)

	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	if err := writeBundleReferrer(subject, bundleWithDSSEPayload(t, payload), testPredicateType, nil, nil); err != nil {
		t.Fatalf("writing referrer: %v", err)
	}

	opts := []ociremote.Option{ociremote.WithRemoteOptions()}

	// Find the existing referrer's digest so we can assert it is the one returned.
	matching, err := matchingBundleReferrers(subject, testPredicateType, opts, nil)
	if err != nil {
		t.Fatalf("matchingBundleReferrers: %v", err)
	}
	if len(matching) != 1 {
		t.Fatalf("expected 1 matching referrer, got %d", len(matching))
	}
	want := matching[0].Digest

	// Identical payload: REPUSHSAME must re-push the existing referrer.
	action, matched, err := resolveBundleConflict(subject, testPredicateType, payload, RePushSame, nil, opts)
	if err != nil {
		t.Fatalf("resolveBundleConflict(RePushSame, identical): %v", err)
	}
	if action != bundleRePush {
		t.Errorf("expected REPUSHSAME to re-push an identical payload, got %v", action)
	}
	if matched != want {
		t.Errorf("expected re-push of %s, got %s", want, matched)
	}

	// The re-push itself must succeed and preserve the referrer (same digest).
	if err := repushBundleReferrer(subject, matched, nil); err != nil {
		t.Fatalf("repushBundleReferrer: %v", err)
	}
	after, err := matchingBundleReferrers(subject, testPredicateType, opts, nil)
	if err != nil {
		t.Fatalf("matchingBundleReferrers after re-push: %v", err)
	}
	if len(after) != 1 || after[0].Digest != want {
		t.Fatalf("expected the same single referrer %s after re-push, got %v", want, after)
	}

	// Different payload: REPUSHSAME must request a fresh write.
	action, _, err = resolveBundleConflict(subject, testPredicateType, []byte(`{"_type":"differs"}`), RePushSame, nil, opts)
	if err != nil {
		t.Fatalf("resolveBundleConflict(RePushSame, different): %v", err)
	}
	if action != bundleWrite {
		t.Errorf("expected REPUSHSAME to write a novel payload, got %v", action)
	}
}
