package secant

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/fulcio"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// testFulcio is a counting fake Fulcio with a root, an intermediate and a CT
// log. It issues certs for the requesting keypair, named for the token's
// subject and carrying an embedded SCT, as public Fulcio does.
type testFulcio struct {
	t           *testing.T
	root        *x509.Certificate
	inter       *x509.Certificate
	interKey    *ecdsa.PrivateKey
	ctKey       *ecdsa.PrivateKey
	trustedRoot *root.TrustedRoot
	omitSCT     bool
	otherKey    bool // issue certs for a key other than the requester's

	mu      sync.Mutex
	fetches int
}

func newTestFulcio(t *testing.T) *testFulcio {
	t.Helper()
	rootKey := mustKey(t)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootCert := mustCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

	interKey := mustKey(t)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-fulcio-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interCert := mustCert(t, interTmpl, rootCert, &interKey.PublicKey, rootKey)

	ctKey := mustKey(t)
	logID := ctLogID(t, &ctKey.PublicKey)
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: rootCert, Intermediates: []*x509.Certificate{interCert}}},
		map[string]*root.TransparencyLog{hex.EncodeToString(logID[:]): {
			ID:                logID[:],
			HashFunc:          crypto.SHA256,
			PublicKey:         &ctKey.PublicKey,
			SignatureHashFunc: crypto.SHA256,
		}},
		nil, nil)
	if err != nil {
		t.Fatalf("NewTrustedRoot: %v", err)
	}
	return &testFulcio{t: t, root: rootCert, inter: interCert, interKey: interKey, ctKey: ctKey, trustedRoot: tr}
}

func (f *testFulcio) fetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

// chainPEM is the chain the legacy Fulcio API returns: intermediate, then root.
func (f *testFulcio) chainPEM() string {
	pem, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{f.inter, f.root})
	if err != nil {
		f.t.Fatalf("marshaling chain: %v", err)
	}
	return string(pem)
}

func (f *testFulcio) GetCertificate(_ context.Context, keypair sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	f.mu.Lock()
	f.fetches++
	f.mu.Unlock()

	var claims struct {
		Subject string `json:"sub"`
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(opts.IDToken, ".")[1])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: claims.Subject},
		EmailAddresses: []string{"signer@example.com"},
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       time.Now().Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	pub := keypair.GetPublicKey()
	if f.otherKey {
		pub = &mustKey(f.t).PublicKey
	}
	if f.omitSCT {
		return x509.CreateCertificate(rand.Reader, tmpl, f.inter, pub, f.interKey)
	}

	// Sign an SCT over the precert, then issue the same cert with the SCT
	// embedded; dropping the SCT extension gives back the precert's TBS.
	precert := mustCert(f.t, tmpl, f.inter, pub, f.interKey)
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: ctLogID(f.t, &f.ctKey.PublicKey)},
		Timestamp:  uint64(time.Now().UnixMilli()),
	}
	input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: sct.Timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(f.inter.RawSubjectPublicKeyInfo),
				TBSCertificate: precert.RawTBSCertificate,
			},
		},
	}})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, f.ctKey, digest[:])
	if err != nil {
		return nil, err
	}
	sct.Signature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA},
		Signature: sig,
	}
	sctList, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		return nil, err
	}
	sctBytes, err := cttls.Marshal(*sctList)
	if err != nil {
		return nil, err
	}
	ext, err := asn1.Marshal(sctBytes)
	if err != nil {
		return nil, err
	}
	tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT), Value: ext}}
	return x509.CreateCertificate(rand.Reader, tmpl, f.inter, pub, f.interKey)
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return k
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
	return cert
}

func ctLogID(t *testing.T, pub crypto.PublicKey) [32]byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling CT log key: %v", err)
	}
	return sha256.Sum256(der)
}

// newSharedSigners builds a BundleSigner over f, with no transparency log or
// TSA so it signs offline, and the legacy signer that shares its materials.
func newSharedSigners(t *testing.T, f *testFulcio, tm root.TrustedMaterial) (*BundleSigner, *fulcio.SignerVerifier) {
	t.Helper()
	sc, err := root.NewSigningConfig(root.SigningConfigMediaType02, nil, nil, nil, root.ServiceConfiguration{}, nil, root.ServiceConfiguration{})
	if err != nil {
		t.Fatalf("NewSigningConfig: %v", err)
	}
	bs, err := NewBundleSigner(subjectOIDCProvider{},
		WithSigningConfig(sc),
		WithTrustedMaterial(tm),
		WithCertificateProvider(fulcio.NewCachingCertProvider(f)))
	if err != nil {
		t.Fatalf("NewBundleSigner: %v", err)
	}
	legacy, err := bs.LegacySigner()
	if err != nil {
		t.Fatalf("LegacySigner: %v", err)
	}
	return bs, legacy
}

func TestSharedSignersShareOneCert(t *testing.T) {
	f := newTestFulcio(t)
	bs, legacy := newSharedSigners(t, f, f.trustedRoot)

	verifier, err := verify.NewVerifier(f.trustedRoot, verify.WithSignedCertificateTimestamps(1), verify.WithCurrentTime())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	certs := map[string][]byte{}
	for _, sub := range []string{"org-a/identity", "org-a/identity", "org-b/identity", "org-a/identity", "org-b/identity"} {
		ctx := context.WithValue(context.Background(), subjectCtxKey{}, sub)
		payload := []byte("payload for " + sub)

		// Legacy: the signature verifies with the cert it carries, and the
		// chain annotation is the one the legacy Fulcio API returns.
		sig, err := legacy.Cosign(ctx, bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("Cosign as %s: %v", sub, err)
		}
		legacyCert, err := sig.Cert()
		if err != nil {
			t.Fatalf("legacy cert: %v", err)
		}
		if got := legacyCert.Subject.CommonName; got != sub {
			t.Errorf("legacy signed as %q with a cert for %q", sub, got)
		}
		b64, err := sig.Base64Signature()
		if err != nil {
			t.Fatalf("legacy signature: %v", err)
		}
		rawSig, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("decoding legacy signature: %v", err)
		}
		v, err := signature.LoadVerifier(legacyCert.PublicKey, crypto.SHA256)
		if err != nil {
			t.Fatalf("LoadVerifier: %v", err)
		}
		if err := v.VerifySignature(bytes.NewReader(rawSig), bytes.NewReader(payload)); err != nil {
			t.Errorf("legacy signature as %s does not verify: %v", sub, err)
		}
		ann, err := sig.Annotations()
		if err != nil {
			t.Fatalf("legacy annotations: %v", err)
		}
		if got, want := ann[static.ChainAnnotationKey], f.chainPEM(); got != want {
			t.Errorf("legacy chain annotation = %q, want %q", got, want)
		}

		// Bundle: verifies against the trusted root, with the same cert.
		bundleBytes, err := bs.SignContent(ctx, &sign.PlainData{Data: payload})
		if err != nil {
			t.Fatalf("SignContent as %s: %v", sub, err)
		}
		var b sgbundle.Bundle
		if err := b.UnmarshalJSON(bundleBytes); err != nil {
			t.Fatalf("unmarshaling bundle: %v", err)
		}
		if _, err := verifier.Verify(&b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(payload)), verify.WithoutIdentitiesUnsafe())); err != nil {
			t.Errorf("bundle as %s does not verify: %v", sub, err)
		}
		bundleCert := b.GetVerificationMaterial().GetCertificate().GetRawBytes()
		if !bytes.Equal(bundleCert, legacyCert.Raw) {
			t.Errorf("as %s, the bundle and legacy signatures carry different certs", sub)
		}

		if prev, ok := certs[sub]; ok && !bytes.Equal(prev, legacyCert.Raw) {
			t.Errorf("as %s, signed with a new cert inside one expiry window", sub)
		}
		certs[sub] = legacyCert.Raw
	}

	if got := f.fetchCount(); got != 2 {
		t.Errorf("Fulcio fetches = %d, want 2 (one per identity, shared by both formats)", got)
	}
}

func TestSharedSignerRequiresSCT(t *testing.T) {
	f := newTestFulcio(t)
	f.omitSCT = true
	_, legacy := newSharedSigners(t, f, f.trustedRoot)

	ctx := context.WithValue(context.Background(), subjectCtxKey{}, "org-a/identity")
	_, err := legacy.Cosign(ctx, strings.NewReader("x"))
	if err == nil || !strings.Contains(err.Error(), "verifying SCT") {
		t.Errorf("Cosign with a cert lacking an SCT: err = %v, want an SCT verification error", err)
	}
}

func TestSharedSignerRequiresTrustedChain(t *testing.T) {
	f := newTestFulcio(t)
	other := newTestFulcio(t)
	_, legacy := newSharedSigners(t, f, other.trustedRoot)

	ctx := context.WithValue(context.Background(), subjectCtxKey{}, "org-a/identity")
	_, err := legacy.Cosign(ctx, strings.NewReader("x"))
	if err == nil || !strings.Contains(err.Error(), "verifying cert chain") {
		t.Errorf("Cosign with a cert from an untrusted CA: err = %v, want a chain verification error", err)
	}
}

func TestSharedSignerRequiresCertForItsKey(t *testing.T) {
	f := newTestFulcio(t)
	f.otherKey = true
	_, legacy := newSharedSigners(t, f, f.trustedRoot)

	ctx := context.WithValue(context.Background(), subjectCtxKey{}, "org-a/identity")
	_, err := legacy.Cosign(ctx, strings.NewReader("x"))
	if err == nil || !strings.Contains(err.Error(), "does not bind the signing key") {
		t.Errorf("Cosign with a cert for another key: err = %v, want a key mismatch error", err)
	}
}

// TestSharedSignersConcurrentIdentities signs in both formats as several
// identities at once and checks that every signature carries a cert for the
// identity it was made as, so the shared cache and the legacy signer's chain
// memo never hand one identity's cert to another.
func TestSharedSignersConcurrentIdentities(t *testing.T) {
	f := newTestFulcio(t)
	bs, legacy := newSharedSigners(t, f, f.trustedRoot)

	subs := []string{"org-a/identity", "org-b/identity", "org-c/identity"}
	var wg sync.WaitGroup
	for i := range 60 {
		sub := subs[i%len(subs)]
		wg.Go(func() {
			ctx := context.WithValue(context.Background(), subjectCtxKey{}, sub)
			sig, err := legacy.Cosign(ctx, strings.NewReader(sub))
			if err != nil {
				t.Errorf("Cosign as %s: %v", sub, err)
				return
			}
			cert, err := sig.Cert()
			if err != nil {
				t.Errorf("legacy cert: %v", err)
				return
			}
			if got := cert.Subject.CommonName; got != sub {
				t.Errorf("legacy signed as %q with a cert for %q", sub, got)
			}
			ann, err := sig.Annotations()
			if err != nil {
				t.Errorf("legacy annotations: %v", err)
				return
			}
			certPEM, err := cryptoutils.MarshalCertificateToPEM(cert)
			if err != nil {
				t.Errorf("marshaling cert: %v", err)
				return
			}
			if ann[static.CertificateAnnotationKey] != string(certPEM) {
				t.Errorf("as %s, the certificate annotation does not match the cert", sub)
			}

			bundleBytes, err := bs.SignContent(ctx, &sign.PlainData{Data: []byte(sub)})
			if err != nil {
				t.Errorf("SignContent as %s: %v", sub, err)
				return
			}
			var b sgbundle.Bundle
			if err := b.UnmarshalJSON(bundleBytes); err != nil {
				t.Errorf("unmarshaling bundle: %v", err)
				return
			}
			bundleCert, err := x509.ParseCertificate(b.GetVerificationMaterial().GetCertificate().GetRawBytes())
			if err != nil {
				t.Errorf("parsing bundle cert: %v", err)
				return
			}
			if got := bundleCert.Subject.CommonName; got != sub {
				t.Errorf("bundle signed as %q with a cert for %q", sub, got)
			}
		})
	}
	wg.Wait()

	if got := f.fetchCount(); got != len(subs) {
		t.Errorf("Fulcio fetches = %d, want %d (one per identity)", got, len(subs))
	}
}
