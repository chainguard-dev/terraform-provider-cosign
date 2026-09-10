package secant

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	intotov1 "github.com/in-toto/attestation/go/v1"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestCertNeedsRefreshNilCert(t *testing.T) {
	bs := &BundleSigner{}
	if !bs.certNeedsRefresh() {
		t.Error("expected refresh needed when cert is nil")
	}
}

func TestCertNeedsRefreshValidCert(t *testing.T) {
	_, cert := generateTestCert(t, 10*time.Minute)
	bs := &BundleSigner{cert: cert}
	if bs.certNeedsRefresh() {
		t.Error("expected no refresh needed when cert is valid for 10 minutes")
	}
}

func TestCertNeedsRefreshExpiredCert(t *testing.T) {
	_, cert := generateTestCert(t, -1*time.Minute)
	bs := &BundleSigner{cert: cert}
	if !bs.certNeedsRefresh() {
		t.Error("expected refresh needed when cert is expired")
	}
}

func TestCertNeedsRefreshNearExpiry(t *testing.T) {
	// 10 seconds remaining is within the 30-second buffer.
	_, cert := generateTestCert(t, 10*time.Second)
	bs := &BundleSigner{cert: cert}
	if !bs.certNeedsRefresh() {
		t.Error("expected refresh needed when cert expires within 30s buffer")
	}
}

func TestCacheCertFromBundle(t *testing.T) {
	certPEM, cert := generateTestCert(t, 10*time.Minute)
	derBlock, _ := pem.Decode(certPEM)
	bundleJSON := buildTestBundleJSONCertificate(t, derBlock.Bytes)

	bs := &BundleSigner{}
	if err := bs.cacheCertFromBundle(bundleJSON); err != nil {
		t.Fatalf("cacheCertFromBundle: %v", err)
	}

	if bs.cert == nil {
		t.Fatal("expected cert to be cached")
	}
	if bs.cert.NotAfter != cert.NotAfter {
		t.Errorf("cached cert NotAfter = %v, want %v", bs.cert.NotAfter, cert.NotAfter)
	}
	if len(bs.certPEM) == 0 {
		t.Error("expected certPEM to be set")
	}
}

func TestCacheCertFromBundleNoCerts(t *testing.T) {
	// Bundle with empty verification material.
	bundleJSON := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{}}`)
	bs := &BundleSigner{}
	if err := bs.cacheCertFromBundle(bundleJSON); err == nil {
		t.Fatal("expected error when bundle has no certificate")
	}
}

// generateTestCert creates a self-signed certificate valid for the given duration.
// Negative durations produce already-expired certificates.
func generateTestCert(t *testing.T, validity time.Duration) ([]byte, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(validity),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return certPEM, cert
}

// buildTestBundleJSONCertificate creates a v0.3 protobuf bundle JSON using
// VerificationMaterial.Certificate (the form cbundle.SignData emits).
func buildTestBundleJSONCertificate(t *testing.T, certDER []byte) []byte {
	t.Helper()

	bundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: certDER},
			},
		},
	}

	data, err := protojson.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshaling test bundle: %v", err)
	}
	return data
}

// fakeContentSigner stands in for BundleSigner: it wraps each DSSE payload it
// is asked to sign in a minimal bundle and counts invocations.
type fakeContentSigner struct {
	t     *testing.T
	calls int
}

func (f *fakeContentSigner) SignContent(_ context.Context, content sign.Content) ([]byte, error) {
	f.calls++
	dsse, ok := content.(*sign.DSSEData)
	if !ok {
		f.t.Fatalf("SignContent() got content type %T, want *sign.DSSEData", content)
	}
	return bundleWithDSSEPayload(f.t, dsse.Data), nil
}

// TestSignBundleWalksIndexChildren mirrors TestSign for the bundle path: the
// walk must attach a sign-predicate bundle to the index and to each child
// manifest, each bundle's statement naming that entity as its subject.
func TestSignBundleWalksIndexChildren(t *testing.T) {
	ctx := context.Background()

	for _, referrersSupport := range []bool{true, false} {
		t.Run(fmt.Sprintf("referrersSupport=%t", referrersSupport), func(t *testing.T) {
			repo, rec := newRecordingTestRepo(t, referrersSupport)

			idx, err := random.Index(1024, 1, 2)
			if err != nil {
				t.Fatal(err)
			}
			if err := remote.WriteIndex(repo.Tag("latest"), idx); err != nil {
				t.Fatal(err)
			}

			im, err := idx.IndexManifest()
			if err != nil {
				t.Fatal(err)
			}
			h, err := idx.Digest()
			if err != nil {
				t.Fatal(err)
			}
			digests := []name.Digest{repo.Digest(h.String())}
			for _, m := range im.Manifests {
				digests = append(digests, repo.Digest(m.Digest.String()))
			}
			rec.reset()

			signer := &fakeContentSigner{t: t}
			if err := signBundle(ctx, SkipSame, nil, signer, digests[:1], nil); err != nil {
				t.Fatalf("signBundle() = %v", err)
			}

			// The walk signs the index and each of its children, and every
			// bundle's statement names the entity it is attached to.
			for _, d := range digests {
				assertOneSignBundle(t, d)
			}
			if signer.calls != len(digests) {
				t.Errorf("got %d sign operations, want %d", signer.calls, len(digests))
			}

			// The walk already fetched every entity, so the referrer subject
			// descriptors come from those fetches — no HEAD per entity — and
			// carry the media type, digest and size a HEAD would have returned.
			for _, d := range digests {
				if heads := rec.subjectRequests(d, http.MethodHead); len(heads) != 0 {
					t.Errorf("subject %s was HEADed: %v", d, heads)
				}
			}
			for _, d := range digests {
				want, err := remote.Head(d)
				if err != nil {
					t.Fatal(err)
				}
				for _, got := range signBundleSubjects(t, d) {
					if got == nil {
						t.Fatalf("sign bundle for %s has no subject descriptor", d)
					}
					if got.MediaType != want.MediaType || got.Digest != want.Digest || got.Size != want.Size {
						t.Errorf("sign bundle subject for %s = %+v, want {%s %s %d}", d, *got, want.MediaType, want.Digest, want.Size)
					}
				}
			}

			// A SKIPSAME re-run finds every bundle already in place and signs
			// nothing.
			signer.calls = 0
			if err := signBundle(ctx, SkipSame, nil, signer, digests[:1], nil); err != nil {
				t.Fatalf("signBundle() re-run = %v", err)
			}
			if signer.calls != 0 {
				t.Errorf("re-run performed %d sign operations, want 0", signer.calls)
			}
			for _, d := range digests {
				if got := len(signBundleStatements(t, d)); got != 1 {
					t.Errorf("got %d sign bundles for %s after re-run, want 1", got, d)
				}
			}

			// A REPLACE run re-signs every walked entity — pinning that the
			// caller's conflict mode reaches the per-digest path — and still
			// converges on one bundle per digest.
			signer.calls = 0
			if err := signBundle(ctx, Replace, nil, signer, digests[:1], nil); err != nil {
				t.Fatalf("signBundle() REPLACE = %v", err)
			}
			if signer.calls != len(digests) {
				t.Errorf("REPLACE run performed %d sign operations, want %d", signer.calls, len(digests))
			}
			for _, d := range digests {
				if got := len(signBundleStatements(t, d)); got != 1 {
					t.Errorf("got %d sign bundles for %s after REPLACE, want 1", got, d)
				}
			}
		})
	}
}

// signBundleSubjects returns the subject descriptor of each sign-predicate
// bundle referrer manifest attached to d.
func signBundleSubjects(t *testing.T, d name.Digest) []*v1.Descriptor {
	t.Helper()

	matching, err := matchingBundleReferrers(d, ctypes.CosignSignPredicateType, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	subjects := make([]*v1.Descriptor, 0, len(matching))
	for _, m := range matching {
		desc, err := remote.Get(d.Context().Digest(m.Digest.String()))
		if err != nil {
			t.Fatal(err)
		}
		mf, err := v1.ParseManifest(bytes.NewReader(desc.Manifest))
		if err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, mf.Subject)
	}
	return subjects
}

// signBundleStatements returns the DSSE statement payload of each
// sign-predicate bundle referrer attached to d.
func signBundleStatements(t *testing.T, d name.Digest) [][]byte {
	t.Helper()

	matching, err := matchingBundleReferrers(d, ctypes.CosignSignPredicateType, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payloads := make([][]byte, 0, len(matching))
	for _, m := range matching {
		p, err := referrerDSSEPayload(d.Repository, m.Digest, nil)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, p)
	}
	return payloads
}

// recordingRegistry logs every request served by a test registry, so a test
// can prove which manifests the code under test did not touch.
type recordingRegistry struct {
	mu   sync.Mutex
	reqs []string
}

// reset discards requests recorded so far, so a test can separate its own
// setup traffic from the code under test.
func (r *recordingRegistry) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = nil
}

func (r *recordingRegistry) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req.Method+" "+req.URL.Path)
}

// subjectRequests returns the requests with any of the given methods against
// the subject manifest itself, addressed by digest — as opposed to its
// referrers or the sha256-<digest> fallback-tag index, which the writer
// legitimately reads.
func (r *recordingRegistry) subjectRequests(d name.Digest, methods ...string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	path := "/v2/" + d.Context().RepositoryStr() + "/manifests/" + d.DigestStr()
	var reqs []string
	for _, req := range r.reqs {
		for _, m := range methods {
			if req == m+" "+path {
				reqs = append(reqs, req)
			}
		}
	}
	return reqs
}

func newRecordingTestRepo(t *testing.T, referrersSupport bool) (name.Repository, *recordingRegistry) {
	t.Helper()

	rec := &recordingRegistry{}
	reg := registry.New(registry.WithReferrersSupport(referrersSupport))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec.record(req)
		reg.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)

	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test-repo")
	if err != nil {
		t.Fatal(err)
	}
	return repo, rec
}

// assertOneSignBundle checks that exactly one sign-predicate bundle is
// attached to d and that its statement names d as the subject.
func assertOneSignBundle(t *testing.T, d name.Digest) {
	t.Helper()

	statements := signBundleStatements(t, d)
	if len(statements) != 1 {
		t.Fatalf("got %d sign bundles for %s, want 1", len(statements), d)
	}
	statement := &intotov1.Statement{}
	if err := protojson.Unmarshal(statements[0], statement); err != nil {
		t.Fatalf("unmarshaling statement for %s: %v", d, err)
	}
	if got := len(statement.Subject); got != 1 {
		t.Fatalf("got %d statement subjects for %s, want 1", got, d)
	}
	if got, want := "sha256:"+statement.Subject[0].Digest["sha256"], d.DigestStr(); got != want {
		t.Errorf("statement subject = %s, want %s", got, want)
	}
}

// TestSignBundleDigestSignsUnpushedSubjectWithoutFetching pins the contract
// that distinguishes SignBundleDigest from SignBundle: it signs a digest whose
// manifest is not in the registry yet and never reads the subject manifest,
// so a caller may sign while the push is still in flight.
func TestSignBundleDigestSignsUnpushedSubjectWithoutFetching(t *testing.T) {
	ctx := context.Background()

	for _, referrersSupport := range []bool{true, false} {
		t.Run(fmt.Sprintf("referrersSupport=%t", referrersSupport), func(t *testing.T) {
			repo, rec := newRecordingTestRepo(t, referrersSupport)

			// Deliberately not pushed: the subject exists only as a digest.
			img, err := random.Image(1024, 1)
			if err != nil {
				t.Fatal(err)
			}
			h, err := img.Digest()
			if err != nil {
				t.Fatal(err)
			}
			d := repo.Digest(h.String())

			signer := &fakeContentSigner{t: t}
			if err := signBundleDigest(ctx, SkipSame, nil, signer, d, nil, nil, nil); err != nil {
				t.Fatalf("signBundleDigest() = %v", err)
			}
			assertOneSignBundle(t, d)
			if signer.calls != 1 {
				t.Errorf("got %d sign operations, want 1", signer.calls)
			}

			// A SKIPSAME re-run finds the bundle in place and signs nothing.
			signer.calls = 0
			if err := signBundleDigest(ctx, SkipSame, nil, signer, d, nil, nil, nil); err != nil {
				t.Fatalf("signBundleDigest() re-run = %v", err)
			}
			if signer.calls != 0 {
				t.Errorf("re-run performed %d sign operations, want 0", signer.calls)
			}
			assertOneSignBundle(t, d)

			// REPLACE re-signs and still converges on one bundle.
			signer.calls = 0
			if err := signBundleDigest(ctx, Replace, nil, signer, d, nil, nil, nil); err != nil {
				t.Fatalf("signBundleDigest() REPLACE = %v", err)
			}
			if signer.calls != 1 {
				t.Errorf("REPLACE run performed %d sign operations, want 1", signer.calls)
			}
			assertOneSignBundle(t, d)

			// None of the three runs read the subject manifest.
			if reads := rec.subjectRequests(d, http.MethodGet, http.MethodHead); len(reads) != 0 {
				t.Errorf("subject manifest was read: %v", reads)
			}

			// Once the publish lands, the bundle is attached to the real
			// manifest: the registry indexes referrers by the subject digest.
			if err := remote.Write(repo.Tag("latest"), img); err != nil {
				t.Fatal(err)
			}
			assertOneSignBundle(t, d)
		})
	}
}

// TestSignBundleDigestDoesNotWalkIndex is the counterpart of
// TestSignBundleWalksIndexChildren: handed an index, SignBundleDigest signs
// the index alone and leaves its children untouched and unread. Callers that
// enumerate their own children sign each one explicitly.
func TestSignBundleDigestDoesNotWalkIndex(t *testing.T) {
	ctx := context.Background()
	repo, rec := newRecordingTestRepo(t, true)

	idx, err := random.Index(1024, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(repo.Tag("latest"), idx); err != nil {
		t.Fatal(err)
	}
	h, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	d := repo.Digest(h.String())
	children := make([]name.Digest, 0, len(im.Manifests))
	for _, m := range im.Manifests {
		children = append(children, repo.Digest(m.Digest.String()))
	}
	// WriteIndex above probes manifests before pushing; only the code under
	// test's traffic is of interest.
	rec.reset()

	signer := &fakeContentSigner{t: t}
	if err := signBundleDigest(ctx, SkipSame, nil, signer, d, nil, nil, nil); err != nil {
		t.Fatalf("signBundleDigest() = %v", err)
	}
	assertOneSignBundle(t, d)
	if signer.calls != 1 {
		t.Errorf("got %d sign operations, want 1", signer.calls)
	}
	for _, c := range children {
		if got := len(signBundleStatements(t, c)); got != 0 {
			t.Errorf("got %d sign bundles for child %s, want 0", got, c)
		}
		if reads := rec.subjectRequests(c, http.MethodGet, http.MethodHead); len(reads) != 0 {
			t.Errorf("child manifest %s was read: %v", c, reads)
		}
	}
	if reads := rec.subjectRequests(d, http.MethodGet, http.MethodHead); len(reads) != 0 {
		t.Errorf("index manifest was read: %v", reads)
	}
}
