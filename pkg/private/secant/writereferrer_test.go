package secant

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

const testPredicateType = "https://slsa.dev/provenance/v1"

var testBundleBytes = []byte(`{"this":"stands in for a serialized sigstore bundle"}`)

func setupTestRepo(t *testing.T) name.Repository {
	t.Helper()

	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)

	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test-repo")
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func pushRandomImage(t *testing.T, repo name.Repository) name.Digest {
	t.Helper()

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(repo.Tag("latest"), img); err != nil {
		t.Fatal(err)
	}
	h, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return repo.Digest(h.String())
}

// referrerManifests fetches the raw manifest of every referrer of d.
func referrerManifests(t *testing.T, d name.Digest) [][]byte {
	t.Helper()

	idx, err := remote.Referrers(d)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	raws := make([][]byte, 0, len(im.Manifests))
	for _, m := range im.Manifests {
		desc, err := remote.Get(d.Context().Digest(m.Digest.String()))
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, desc.Manifest)
	}
	return raws
}

// normalizeManifest parses a raw manifest and drops the created annotation,
// the only field expected to vary between writers.
func normalizeManifest(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if ann, ok := m["annotations"].(map[string]any); ok {
		delete(ann, "org.opencontainers.image.created")
	}
	return m
}

// TestWriteBundleReferrerParity pins writeBundleReferrer's nil-subject output to
// cosign's WriteAttestationNewBundleFormat for the life of the fork: modulo the
// created timestamp, the two must produce identical referrer manifests.
func TestWriteBundleReferrerParity(t *testing.T) {
	repo := setupTestRepo(t)
	d := pushRandomImage(t, repo)

	if err := ociremote.WriteAttestationNewBundleFormat(d, testBundleBytes, testPredicateType); err != nil {
		t.Fatalf("cosign WriteAttestationNewBundleFormat: %v", err)
	}
	if err := writeBundleReferrer(d, testBundleBytes, testPredicateType, nil, nil); err != nil {
		t.Fatalf("writeBundleReferrer: %v", err)
	}

	// If both writes land in the same second the manifests are byte-identical
	// and the registry dedups them into a single referrer; otherwise they
	// differ only in the created annotation.
	raws := referrerManifests(t, d)
	if len(raws) == 0 {
		t.Fatal("no referrers found")
	}
	want := normalizeManifest(t, raws[0])
	for _, raw := range raws[1:] {
		if got := normalizeManifest(t, raw); !reflect.DeepEqual(got, want) {
			t.Errorf("referrer manifests diverge:\ngot:  %v\nwant: %v", got, want)
		}
	}
}

// TestWriteBundleReferrerVerbatimSubject covers the synthetic-subject path: the
// subject manifest exists nowhere, and the caller-supplied descriptor must appear
// in the referrer manifest exactly as given.
func TestWriteBundleReferrerVerbatimSubject(t *testing.T) {
	repo := setupTestRepo(t)
	d := repo.Digest("sha256:" + strings.Repeat("ab", 32))

	h, err := v1.NewHash(d.DigestStr())
	if err != nil {
		t.Fatal(err)
	}
	subject := &v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    h,
	}

	if err := writeBundleReferrer(d, testBundleBytes, testPredicateType, subject, nil); err != nil {
		t.Fatalf("writeBundleReferrer: %v", err)
	}

	raws := referrerManifests(t, d)
	if len(raws) != 1 {
		t.Fatalf("expected 1 referrer, got %d", len(raws))
	}

	var manifest struct {
		v1.Manifest
		ArtifactType string `json:"artifactType"`
	}
	if err := json.Unmarshal(raws[0], &manifest); err != nil {
		t.Fatal(err)
	}

	if manifest.Subject == nil {
		t.Fatal("referrer manifest has no subject")
	}
	if !reflect.DeepEqual(manifest.Subject, subject) {
		t.Errorf("subject not verbatim:\ngot:  %+v\nwant: %+v", manifest.Subject, subject)
	}
	// The synthetic descriptor must serialize an explicit zero size.
	if !strings.Contains(string(raws[0]), `"size":0`) {
		t.Errorf("expected explicit \"size\":0 in subject descriptor: %s", raws[0])
	}

	bundleMediaType, err := sgbundle.MediaTypeString("0.3")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ArtifactType != bundleMediaType {
		t.Errorf("artifactType = %q, want %q", manifest.ArtifactType, bundleMediaType)
	}
	if got := manifest.Annotations[ociremote.BundlePredicateType]; got != testPredicateType {
		t.Errorf("predicate type annotation = %q, want %q", got, testPredicateType)
	}
}

// TestWriteBundleReferrerSubjectDigestMismatch verifies that a caller-supplied
// descriptor whose digest differs from the target digest is rejected: the
// registry would index the referrer under the descriptor's digest, making it
// undiscoverable via the digest being attested.
func TestWriteBundleReferrerSubjectDigestMismatch(t *testing.T) {
	repo := setupTestRepo(t)
	d := repo.Digest("sha256:" + strings.Repeat("ab", 32))

	h, err := v1.NewHash("sha256:" + strings.Repeat("ef", 32))
	if err != nil {
		t.Fatal(err)
	}
	subject := &v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    h,
	}

	err = writeBundleReferrer(d, testBundleBytes, testPredicateType, subject, nil)
	if err == nil {
		t.Fatal("expected error for mismatched subject descriptor digest, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestWriteBundleReferrerNilSubjectMissing verifies the strict behavior restored
// from cosign: with no caller-supplied descriptor, a missing subject manifest is
// an error rather than a silently degraded referrer.
func TestWriteBundleReferrerNilSubjectMissing(t *testing.T) {
	repo := setupTestRepo(t)
	d := repo.Digest("sha256:" + strings.Repeat("cd", 32))

	if err := writeBundleReferrer(d, testBundleBytes, testPredicateType, nil, nil); err == nil {
		t.Fatal("expected error for missing subject with nil descriptor, got nil")
	}
}
