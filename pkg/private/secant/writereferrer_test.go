package secant

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
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

func pushImage(t *testing.T, repo name.Repository, img v1.Image) name.Digest {
	t.Helper()

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
// created timestamp, the two must produce identical referrer manifests. Each
// implementation writes into its own repository (holding the same image) so the
// test always compares exactly two independently-written manifests, with no
// registry dedup when both land in the same second.
func TestWriteBundleReferrerParity(t *testing.T) {
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	cosignD := pushImage(t, setupTestRepo(t), img)
	forkD := pushImage(t, setupTestRepo(t), img)

	if err := ociremote.WriteAttestationNewBundleFormat(cosignD, testBundleBytes, testPredicateType); err != nil {
		t.Fatalf("cosign WriteAttestationNewBundleFormat: %v", err)
	}
	if err := writeBundleReferrer(forkD, testBundleBytes, testPredicateType, nil, nil); err != nil {
		t.Fatalf("writeBundleReferrer: %v", err)
	}

	cosignRaws := referrerManifests(t, cosignD)
	if len(cosignRaws) != 1 {
		t.Fatalf("expected 1 cosign referrer, got %d", len(cosignRaws))
	}
	forkRaws := referrerManifests(t, forkD)
	if len(forkRaws) != 1 {
		t.Fatalf("expected 1 fork referrer, got %d", len(forkRaws))
	}

	want := normalizeManifest(t, cosignRaws[0])
	if diff := cmp.Diff(want, normalizeManifest(t, forkRaws[0])); diff != "" {
		t.Errorf("referrer manifests diverge (-cosign +fork):\n%s", diff)
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

	var got referrerManifest
	if err := json.Unmarshal(raws[0], &got); err != nil {
		t.Fatal(err)
	}

	// The synthetic descriptor must serialize an explicit zero size.
	var rawFields struct {
		Subject map[string]json.RawMessage `json:"subject"`
	}
	if err := json.Unmarshal(raws[0], &rawFields); err != nil {
		t.Fatal(err)
	}
	if size, ok := rawFields.Subject["size"]; !ok || string(size) != "0" {
		t.Errorf("expected explicit \"size\":0 in subject descriptor: %s", raws[0])
	}

	bundleMediaType, err := sgbundle.MediaTypeString("0.3")
	if err != nil {
		t.Fatal(err)
	}
	configDesc, err := layerDescriptor(static.NewLayer([]byte("{}"), "application/vnd.oci.image.config.v1+json"))
	if err != nil {
		t.Fatal(err)
	}
	bundleDesc, err := layerDescriptor(static.NewLayer(testBundleBytes, types.MediaType(bundleMediaType)))
	if err != nil {
		t.Fatal(err)
	}

	created := got.Annotations["org.opencontainers.image.created"]
	if _, err := time.Parse(time.RFC3339, created); err != nil {
		t.Errorf("created annotation %q is not RFC3339: %v", created, err)
	}

	// The constructor is pinned field-by-field in TestNewReferrerManifest, so it
	// serves as want here: this asserts the write path lands the constructed
	// manifest in the registry unchanged.
	want := newReferrerManifest(configDesc, bundleDesc, subject, bundleMediaType, testPredicateType)
	want.Annotations["org.opencontainers.image.created"] = created
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("referrer manifest mismatch (-want +got):\n%s", diff)
	}

	// The bundle blob itself must round-trip through the registry.
	layer, err := remote.Layer(repo.Digest(bundleDesc.Digest.String()))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := layer.Compressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	gotBundle, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBundle, testBundleBytes) {
		t.Errorf("bundle blob round-trip mismatch:\ngot:  %s\nwant: %s", gotBundle, testBundleBytes)
	}
}

// TestNewReferrerManifest compares the assembled manifest against the expected
// layout wholesale. The created annotation is the only non-deterministic field:
// it is checked to be well-formed RFC3339 and then copied into want.
func TestNewReferrerManifest(t *testing.T) {
	bundleMediaType, err := sgbundle.MediaTypeString("0.3")
	if err != nil {
		t.Fatal(err)
	}

	configDigest, err := v1.NewHash("sha256:" + strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	configDesc := v1.Descriptor{
		MediaType: types.MediaType("application/vnd.oci.image.config.v1+json"),
		Digest:    configDigest,
		Size:      2,
	}

	bundleDigest, err := v1.NewHash("sha256:" + strings.Repeat("22", 32))
	if err != nil {
		t.Fatal(err)
	}
	bundleDesc := v1.Descriptor{
		MediaType: types.MediaType(bundleMediaType),
		Digest:    bundleDigest,
		Size:      int64(len(testBundleBytes)),
	}

	subjectDigest, err := v1.NewHash("sha256:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	subject := &v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    subjectDigest,
	}

	got := newReferrerManifest(configDesc, bundleDesc, subject, bundleMediaType, testPredicateType)

	created := got.Annotations["org.opencontainers.image.created"]
	if _, err := time.Parse(time.RFC3339, created); err != nil {
		t.Errorf("created annotation %q is not RFC3339: %v", created, err)
	}

	want := referrerManifest{
		Manifest: v1.Manifest{
			SchemaVersion: 2,
			MediaType:     types.OCIManifestSchema1,
			Config: v1.Descriptor{
				MediaType:    types.MediaType("application/vnd.oci.empty.v1+json"),
				ArtifactType: bundleMediaType,
				Digest:       configDesc.Digest,
				Size:         configDesc.Size,
			},
			Layers:  []v1.Descriptor{bundleDesc},
			Subject: subject,
			Annotations: map[string]string{
				"org.opencontainers.image.created": created,
				"dev.sigstore.bundle.content":      "dsse-envelope",
				ociremote.BundlePredicateType:      testPredicateType,
			},
		},
		ArtifactType: bundleMediaType,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("referrer manifest mismatch (-want +got):\n%s", diff)
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
