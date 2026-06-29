package secant

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	dsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
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

// bundleN returns testBundleBytes mutated so each call produces a distinct
// referrer manifest digest (mirroring successive status writes with different
// payloads).
func bundleN(n int) []byte {
	return fmt.Appendf(nil, `{"this":"stands in for a serialized sigstore bundle","n":%d}`, n)
}

// TestReplaceNoDangling drives two consecutive REPLACE writes for the same
// subject + predicate type and asserts that exactly one consistent referrer
// remains afterward, on both registry topologies.
//
// On a registry WITHOUT native Referrers API support this reproduces the bug
// where REPLACE deletes the prior referrer manifest but leaves a dangling
// descriptor in the sha256-<subject> fallback index. The second write's
// commitSubjectReferrers then reads the stale index, appends the new
// descriptor, and re-PUTs an index that still references the just-deleted
// manifest; a registry that validates index members rejects the PUT with
// MANIFEST_UNKNOWN. On a registry WITH native referrers support there is no
// fallback index, so this is the control that confirms the same flow stays
// clean.
//
// This drives the same code paths as two AttestBundle(..., Replace, ...) /
// SignBundle(..., Replace, ...) writes (resolveBundleConflict + writeBundleReferrer)
// without needing a real Fulcio/Rekor signer.
func TestReplaceNoDangling(t *testing.T) {
	for _, tc := range []struct {
		name             string
		referrersSupport bool
	}{
		{"fallback tag index", false},
		{"native referrers api", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newTestRepo(t, tc.referrersSupport)

			img, err := random.Image(1024, 1)
			if err != nil {
				t.Fatal(err)
			}
			subject := pushImage(t, repo, img)

			ociOpts := []ociremote.Option{ociremote.WithRemoteOptions()}

			// First write.
			if _, err := resolveBundleConflict(subject, testPredicateType, bundleN(1), Replace, nil, ociOpts); err != nil {
				t.Fatalf("first resolveBundleConflict: %v", err)
			}
			if err := writeBundleReferrer(subject, bundleN(1), testPredicateType, nil, nil); err != nil {
				t.Fatalf("first writeBundleReferrer: %v", err)
			}

			// Second Replace write for the same subject + predicate type. On the
			// fallback topology, pre-fix this fails inside commitSubjectReferrers
			// because the fallback index still lists the referrer deleted by
			// resolveBundleConflict.
			if _, err := resolveBundleConflict(subject, testPredicateType, bundleN(2), Replace, nil, ociOpts); err != nil {
				t.Fatalf("second resolveBundleConflict: %v", err)
			}
			if err := writeBundleReferrer(subject, bundleN(2), testPredicateType, nil, nil); err != nil {
				t.Fatalf("second writeBundleReferrer: %v", err)
			}

			// Exactly one referrer must remain after the second Replace.
			raws := referrerManifests(t, subject)
			if len(raws) != 1 {
				t.Fatalf("expected exactly 1 referrer after second Replace, got %d", len(raws))
			}

			// And the fallback index (if any) must reference only manifests that
			// still exist. A no-op on the native registry, which has no fallback tag.
			assertFallbackIndexConsistent(t, subject)
		})
	}
}

// TestPruneFallbackReferrersClearsDangling isolates the fallback-index dangling
// bug from the referrer-matching bug. It writes a referrer, deletes its manifest
// the way resolveBundleConflict's REPLACE branch does (remote.Delete, which does
// not touch the fallback index), and then verifies that a fresh write succeeds.
// It is inherently fallback-specific: a native-referrers registry has no
// fallback index to leave dangling.
//
// Without pruning, the second write's commitSubjectReferrers reads the stale
// sha256-<subject> index (still listing the deleted referrer), re-PUTs it with
// the new descriptor appended, and the in-memory registry rejects the index PUT
// with MANIFEST_UNKNOWN ("Sub-manifest <deleted digest> not found").
func TestPruneFallbackReferrersClearsDangling(t *testing.T) {
	repo := newTestRepo(t, false)

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	subject := pushImage(t, repo, img)

	// Write a first referrer.
	if err := writeBundleReferrer(subject, bundleN(1), testPredicateType, nil, nil); err != nil {
		t.Fatalf("first writeBundleReferrer: %v", err)
	}

	// Find and delete it by digest, mirroring resolveBundleConflict's delete loop.
	raws := referrerManifests(t, subject)
	if len(raws) != 1 {
		t.Fatalf("expected 1 referrer after first write, got %d", len(raws))
	}
	idx, err := remote.Referrers(subject)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	deleted := make([]v1.Hash, 0, len(im.Manifests))
	for _, m := range im.Manifests {
		if err := remote.Delete(subject.Context().Digest(m.Digest.String())); err != nil {
			t.Fatalf("deleting referrer %s: %v", m.Digest, err)
		}
		deleted = append(deleted, m.Digest)
	}

	// Prune the fallback index (the fix). Pre-fix this is a no-op and the next
	// write fails; post-fix it removes the dangling descriptor.
	if err := pruneFallbackReferrers(subject, deleted, nil); err != nil {
		t.Fatalf("pruneFallbackReferrers: %v", err)
	}

	// A subsequent write must succeed and leave exactly one referrer.
	if err := writeBundleReferrer(subject, bundleN(2), testPredicateType, nil, nil); err != nil {
		t.Fatalf("second writeBundleReferrer (dangling fallback entry): %v", err)
	}
	if got := referrerManifests(t, subject); len(got) != 1 {
		t.Fatalf("expected exactly 1 referrer after prune + rewrite, got %d", len(got))
	}
	assertFallbackIndexConsistent(t, subject)
}

// TestBundleReferrerMatches exercises bundleReferrerMatches's fast and slow
// paths directly with synthetic referrers-index descriptors. The in-memory
// registry never populates a referrers-index descriptor with both a bundle
// artifactType and the predicate-type annotation (its native handler reports the
// config media type and no annotations, and its fallback index omits
// annotations), so neither TestReplaceNoDangling topology reaches the fast path.
// Real registries (zot/GAR/ECR) do populate those fields, making the fast path
// the production-relevant branch — this is its only coverage.
//
// The fast-path cases deliberately point at a missing or contradictory manifest
// so that a regression which fell through to a manifest fetch would flip the
// result, pinning "trust the index when it is populated".
func TestBundleReferrerMatches(t *testing.T) {
	repo := newTestRepo(t, false)

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	subject := pushImage(t, repo, img)

	// One real referrer manifest carrying testPredicateType, so the slow path has
	// an authoritative manifest to consult.
	if err := writeBundleReferrer(subject, bundleN(1), testPredicateType, nil, nil); err != nil {
		t.Fatalf("writeBundleReferrer: %v", err)
	}
	idx, err := remote.Referrers(subject)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(im.Manifests) != 1 {
		t.Fatalf("expected 1 referrer, got %d", len(im.Manifests))
	}
	realDigest := im.Manifests[0].Digest

	bundleMediaType, err := sgbundle.MediaTypeString("0.3")
	if err != nil {
		t.Fatal(err)
	}
	const otherPredicateType = "https://example.com/other/v1"
	missing, err := v1.NewHash("sha256:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		desc      v1.Descriptor
		predicate string
		want      bool
	}{
		{
			// Fast path: index carries bundle artifactType + matching predicate
			// annotation. Digest is absent, so a stray manifest fetch would 404 and
			// return false — want=true proves the index alone decided it.
			name: "fast path match, index trusted without fetch",
			desc: v1.Descriptor{
				Digest:       missing,
				ArtifactType: bundleMediaType,
				Annotations:  map[string]string{ociremote.BundlePredicateType: testPredicateType},
			},
			predicate: testPredicateType,
			want:      true,
		},
		{
			// Fast path: index annotation names a different predicate. Digest points
			// at the real manifest, whose predicate WOULD match — want=false proves
			// the index annotation is authoritative and the manifest is not consulted.
			name: "fast path predicate mismatch, manifest not consulted",
			desc: v1.Descriptor{
				Digest:       realDigest,
				ArtifactType: bundleMediaType,
				Annotations:  map[string]string{ociremote.BundlePredicateType: otherPredicateType},
			},
			predicate: testPredicateType,
			want:      false,
		},
		{
			// A non-bundle, non-empty artifactType must NOT short-circuit to a
			// non-match: the OCI referrers spec lets a registry report the config
			// descriptor's media type as the artifactType, and cosign bundles use the
			// empty-config media type, so a real bundle can surface in the index with
			// artifactType "application/vnd.oci.empty.v1+json" (exactly what
			// go-containerregistry's in-memory native registry does). Digest points at
			// the real bundle manifest, and want=true confirms we fall through to the
			// authoritative manifest instead of trusting the non-bundle artifactType.
			// This pins why bundleReferrerMatches cannot skip the fetch on a
			// non-bundle artifactType.
			name: "non-bundle artifactType still consults manifest",
			desc: v1.Descriptor{
				Digest:       realDigest,
				ArtifactType: "application/vnd.oci.empty.v1+json",
			},
			predicate: testPredicateType,
			want:      true,
		},
		{
			// Slow path: bundle artifactType but no annotation (the ggcr fallback
			// shape). The real manifest carries testPredicateType.
			name: "slow path, annotation absent, manifest matches",
			desc: v1.Descriptor{
				Digest:       realDigest,
				ArtifactType: bundleMediaType,
			},
			predicate: testPredicateType,
			want:      true,
		},
		{
			// Slow path: same manifest, queried for a different predicate type.
			name: "slow path, manifest predicate differs",
			desc: v1.Descriptor{
				Digest: realDigest,
			},
			predicate: otherPredicateType,
			want:      false,
		},
		{
			// Slow path: descriptor for an already-deleted manifest (dangling
			// fallback-index entry) is not a match and not an error.
			name: "slow path, dangling referrer 404s to non-match",
			desc: v1.Descriptor{
				Digest: missing,
			},
			predicate: testPredicateType,
			want:      false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bundleReferrerMatches(subject.Context(), tc.desc, tc.predicate, nil)
			if err != nil {
				t.Fatalf("bundleReferrerMatches: %v", err)
			}
			if got != tc.want {
				t.Errorf("bundleReferrerMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

// assertFallbackIndexConsistent fetches the sha256-<subject> fallback-tag index
// directly and verifies every descriptor it lists resolves to a real manifest.
// On a registry with native Referrers API support there is no fallback tag, so
// the index GET 404s and this returns without asserting anything.
func assertFallbackIndexConsistent(t *testing.T, subject name.Digest) {
	t.Helper()

	tag := subject.Context().Tag(strings.Replace(subject.DigestStr(), ":", "-", 1))
	idx, err := remote.Index(tag)
	if err != nil {
		// No fallback tag (native referrers, or nothing written) is fine.
		return
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatalf("parsing fallback index: %v", err)
	}
	for _, desc := range im.Manifests {
		if _, err := remote.Get(subject.Context().Digest(desc.Digest.String())); err != nil {
			t.Errorf("fallback index references missing manifest %s: %v", desc.Digest, err)
		}
	}
}
