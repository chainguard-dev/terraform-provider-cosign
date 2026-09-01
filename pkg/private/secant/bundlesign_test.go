package secant

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
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
// manifest, each bundle's statement naming that entity as its subject. Before
// the walk, only the index was signed, leaving arch-pinned digests of a
// bundle-only image unverifiable (CON-2628).
func TestSignBundleWalksIndexChildren(t *testing.T) {
	ctx := context.Background()

	for _, referrersSupport := range []bool{true, false} {
		t.Run(fmt.Sprintf("referrersSupport=%t", referrersSupport), func(t *testing.T) {
			repo := newTestRepo(t, referrersSupport)

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

			signer := &fakeContentSigner{t: t}
			if err := signBundle(ctx, SkipSame, nil, signer, digests[:1], nil); err != nil {
				t.Fatalf("signBundle() = %v", err)
			}

			// The walk signs the index and each of its children, and every
			// bundle's statement names the entity it is attached to.
			for _, d := range digests {
				statements := signBundleStatements(t, d)
				if len(statements) != 1 {
					t.Errorf("got %d sign bundles for %s, want 1", len(statements), d)
					continue
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
			if signer.calls != len(digests) {
				t.Errorf("got %d sign operations, want %d", signer.calls, len(digests))
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
		})
	}
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
