package secant

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
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
