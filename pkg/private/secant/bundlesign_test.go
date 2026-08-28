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
	"errors"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
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

// fakeOIDCProvider implements fulcio.OIDCProvider with a canned token.
type fakeOIDCProvider struct {
	calls atomic.Int32
}

func (f *fakeOIDCProvider) Enabled(context.Context) bool { return true }

func (f *fakeOIDCProvider) Provide(context.Context, string) (string, error) {
	f.calls.Add(1)
	return "fake-token", nil
}

// stubSignData replaces the signData seam for the duration of the test.
func stubSignData(t *testing.T, fn func(context.Context, sign.Content, sign.Keypair, string, []byte, []byte, *root.SigningConfig, root.TrustedMaterial, cbundle.SignOptions) ([]byte, error)) {
	t.Helper()
	prev := signData
	signData = fn
	t.Cleanup(func() { signData = prev })
}

func setBundleBackoff(t *testing.T, d time.Duration) {
	t.Helper()
	prev := bundleSignInitialBackoff
	bundleSignInitialBackoff = d
	t.Cleanup(func() { bundleSignInitialBackoff = prev })
}

// counterValue returns the current value of a prometheus counter.
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("writing metric: %v", err)
	}
	return m.GetCounter().GetValue()
}

// bundleWaitSampleCount returns how many waits the bundle rate limiter has
// recorded, read through reg because the histogram lives unexported in the
// tlog package.
func bundleWaitSampleCount(t *testing.T, reg *prometheus.Registry) uint64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "secant_bundle_rate_limiter_wait_duration_seconds" {
			return mf.GetMetric()[0].GetHistogram().GetSampleCount()
		}
	}
	t.Fatal("bundle rate limiter histogram not registered")
	return 0
}

func TestSignContentRetriesTransient(t *testing.T) {
	setBundleBackoff(t, time.Millisecond)

	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	retriesBefore := counterValue(t, bundleSignRetries)
	waitsBefore := bundleWaitSampleCount(t, reg)

	certPEM, _ := generateTestCert(t, 10*time.Minute)
	derBlock, _ := pem.Decode(certPEM)
	bundleJSON := buildTestBundleJSONCertificate(t, derBlock.Bytes)

	transient := errors.New("stream error: INTERNAL_ERROR")
	var attempts atomic.Int32
	stubSignData(t, func(context.Context, sign.Content, sign.Keypair, string, []byte, []byte, *root.SigningConfig, root.TrustedMaterial, cbundle.SignOptions) ([]byte, error) {
		if attempts.Add(1) < 3 {
			return nil, transient
		}
		return bundleJSON, nil
	})

	provider := &fakeOIDCProvider{}
	bs := &BundleSigner{oidc: provider}

	got, err := bs.SignContent(t.Context(), &sign.DSSEData{Data: []byte("payload")})
	if err != nil {
		t.Fatalf("SignContent: %v", err)
	}
	if !bytes.Equal(got, bundleJSON) {
		t.Error("SignContent returned unexpected bundle bytes")
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
	if got := counterValue(t, bundleSignRetries) - retriesBefore; got != 2 {
		t.Errorf("recorded %v retries, want 2", got)
	}
	// One rate limiter token per attempt, including the first.
	if got, want := bundleWaitSampleCount(t, reg)-waitsBefore, uint64(3); got != want {
		t.Errorf("recorded %d rate limiter waits, want %d", got, want)
	}

	// The successful attempt cached the cert, so a subsequent call takes the
	// steady-state path without another OIDC round-trip.
	if got := provider.calls.Load(); got != 3 {
		t.Errorf("provider calls = %d, want 3 (one per refresh-path attempt)", got)
	}
	if _, err := bs.SignContent(t.Context(), &sign.DSSEData{Data: []byte("payload")}); err != nil {
		t.Fatalf("SignContent with cached cert: %v", err)
	}
	if got := provider.calls.Load(); got != 3 {
		t.Errorf("provider calls after cached-cert sign = %d, want 3", got)
	}
}

func TestSignContentExhaustsAttempts(t *testing.T) {
	setBundleBackoff(t, time.Millisecond)

	persistent := errors.New("persistent failure")
	var attempts atomic.Int32
	stubSignData(t, func(context.Context, sign.Content, sign.Keypair, string, []byte, []byte, *root.SigningConfig, root.TrustedMaterial, cbundle.SignOptions) ([]byte, error) {
		attempts.Add(1)
		return nil, persistent
	})

	bs := &BundleSigner{oidc: &fakeOIDCProvider{}}
	_, err := bs.SignContent(t.Context(), &sign.DSSEData{Data: []byte("payload")})
	if !errors.Is(err, persistent) {
		t.Fatalf("err = %v, want %v", err, persistent)
	}
	if got := attempts.Load(); got != bundleSignMaxAttempts {
		t.Errorf("attempts = %d, want %d", got, bundleSignMaxAttempts)
	}
}

func TestSignContentAbortsOnContextCancel(t *testing.T) {
	// An hour of backoff fails the test by timeout if cancellation doesn't
	// abort the retry loop.
	setBundleBackoff(t, time.Hour)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var attempts atomic.Int32
	stubSignData(t, func(context.Context, sign.Content, sign.Keypair, string, []byte, []byte, *root.SigningConfig, root.TrustedMaterial, cbundle.SignOptions) ([]byte, error) {
		attempts.Add(1)
		cancel()
		return nil, errors.New("boom")
	})

	bs := &BundleSigner{oidc: &fakeOIDCProvider{}}
	if _, err := bs.SignContent(ctx, &sign.DSSEData{Data: []byte("payload")}); err == nil {
		t.Fatal("expected error")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (should abort before second attempt)", got)
	}
}

func TestSignContentRateLimiterGatesFirstAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var attempts atomic.Int32
	stubSignData(t, func(context.Context, sign.Content, sign.Keypair, string, []byte, []byte, *root.SigningConfig, root.TrustedMaterial, cbundle.SignOptions) ([]byte, error) {
		attempts.Add(1)
		return nil, errors.New("boom")
	})

	bs := &BundleSigner{oidc: &fakeOIDCProvider{}}
	_, err := bs.SignContent(ctx, &sign.DSSEData{Data: []byte("payload")})
	if err == nil || !strings.Contains(err.Error(), "waiting for bundle rate limiter") {
		t.Fatalf("err = %v, want bundle rate limiter wait failure", err)
	}
	if got := attempts.Load(); got != 0 {
		t.Errorf("attempts = %d, want 0 (limiter should gate the first attempt)", got)
	}
}

func TestSignContentNilRateLimiter(t *testing.T) {
	prev := BundleRateLimiter
	BundleRateLimiter = nil
	t.Cleanup(func() { BundleRateLimiter = prev })

	certPEM, _ := generateTestCert(t, 10*time.Minute)
	derBlock, _ := pem.Decode(certPEM)
	bundleJSON := buildTestBundleJSONCertificate(t, derBlock.Bytes)

	stubSignData(t, func(context.Context, sign.Content, sign.Keypair, string, []byte, []byte, *root.SigningConfig, root.TrustedMaterial, cbundle.SignOptions) ([]byte, error) {
		return bundleJSON, nil
	})

	bs := &BundleSigner{oidc: &fakeOIDCProvider{}}
	if _, err := bs.SignContent(t.Context(), &sign.DSSEData{Data: []byte("payload")}); err != nil {
		t.Fatalf("SignContent with nil rate limiter: %v", err)
	}
}

func TestSignContentBackoffDoesNotBlockConcurrentSigns(t *testing.T) {
	setBundleBackoff(t, 50*time.Millisecond)

	certPEM, cert := generateTestCert(t, 10*time.Minute)
	derBlock, _ := pem.Decode(certPEM)
	bundleJSON := buildTestBundleJSONCertificate(t, derBlock.Bytes)

	// Seed the cert cache so both calls take the steady-state path.
	bs := &BundleSigner{oidc: &fakeOIDCProvider{}, cert: cert, certPEM: certPEM}

	failing := []byte("failing payload")
	firstFailure := make(chan struct{})
	var once sync.Once
	stubSignData(t, func(_ context.Context, content sign.Content, _ sign.Keypair, _ string, _, _ []byte, _ *root.SigningConfig, _ root.TrustedMaterial, _ cbundle.SignOptions) ([]byte, error) {
		if dsse, ok := content.(*sign.DSSEData); ok && bytes.Equal(dsse.Data, failing) {
			once.Do(func() { close(firstFailure) })
			return nil, errors.New("boom")
		}
		return bundleJSON, nil
	})

	done := make(chan error, 1)
	go func() {
		_, err := bs.SignContent(t.Context(), &sign.DSSEData{Data: failing})
		done <- err
	}()

	// While the failing call backs off between attempts, a healthy sign on
	// the cached-cert path must proceed rather than queue behind it.
	<-firstFailure
	if _, err := bs.SignContent(t.Context(), &sign.DSSEData{Data: []byte("healthy payload")}); err != nil {
		t.Fatalf("concurrent SignContent: %v", err)
	}
	select {
	case <-done:
		t.Error("retrying call finished before the concurrent sign; backoff appears to serialize signs")
	default:
	}
	if err := <-done; err == nil {
		t.Error("expected the failing call to return an error")
	}
}
