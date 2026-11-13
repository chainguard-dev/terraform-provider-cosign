package fulcio

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// sharedCerts is how a SignerVerifier built by NewSharedSigner gets its
// certificates: from a sign.CertificateProvider shared with a bundle signer
// over the same keypair, so both signing formats use one Fulcio certificate.
type sharedCerts struct {
	keypair         sign.Keypair
	certs           sign.CertificateProvider
	trustedMaterial root.TrustedMaterial

	mu       sync.Mutex
	verified map[string]verifiedCert // keyed by DER
}

// verifiedCert is a cert that passed verify, PEM-encoded with its chain.
type verifiedCert struct {
	certPEM, chainPEM []byte
	notAfter          time.Time
}

// NewSharedSigner returns a "keyless" legacy signer that signs with keypair
// and gets its certificates from certs, so that a bundle signer built on the
// same keypair and certs (see secant.BundleSigner.LegacySigner) shares one
// Fulcio certificate per identity with it instead of each fetching its own.
//
// certs is asked for a certificate on every Cosign with the provider's
// current token, so like BundleSigner this signs as the identity of each
// call's token; it must cache certificates itself, as
// CachingCertProvider does.
//
// certs returns only the leaf, so the certificate chain that legacy
// signatures carry is built from the Fulcio CAs in trustedMaterial, and the
// leaf's embedded SCT is verified against its CT logs. trustedMaterial must
// therefore describe the Fulcio instance that certs issues from.
func NewSharedSigner(provider OIDCProvider, keypair sign.Keypair, certs sign.CertificateProvider, trustedMaterial root.TrustedMaterial) (*SignerVerifier, error) {
	if keypair == nil || certs == nil || trustedMaterial == nil {
		return nil, errors.New("keypair, certificate provider and trusted material are required")
	}
	inner, err := newKeypairSignerVerifier(keypair)
	if err != nil {
		return nil, err
	}
	return &SignerVerifier{
		inner:    inner,
		provider: provider,
		shared: &sharedCerts{
			keypair:         keypair,
			certs:           certs,
			trustedMaterial: trustedMaterial,
			verified:        map[string]verifiedCert{},
		},
	}, nil
}

// sharedCertChain returns the PEM-encoded certificate and chain to sign with
// for the provider's current identity, from the shared certificate provider.
func (sv *SignerVerifier) sharedCertChain(ctx context.Context) ([]byte, []byte, error) {
	idToken, err := sv.provider.Provide(ctx, "sigstore")
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving ID token: %w", err)
	}
	der, err := sv.shared.certs.GetCertificate(ctx, sv.shared.keypair, &sign.CertificateProviderOptions{IDToken: idToken})
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving cert: %w", err)
	}

	return sv.shared.chain(der)
}

// chain returns the PEM-encoded cert and chain for der, verifying der the
// first time it is seen. The provider returns the same cert per identity
// until it nears expiry, so a signer that signs as many identities checks
// each identity's chain and SCT once per cert rather than on every switch.
func (s *sharedCerts) chain(der []byte) ([]byte, []byte, error) {
	s.mu.Lock()
	v, ok := s.verified[string(der)]
	s.mu.Unlock()
	if ok {
		return v.certPEM, v.chainPEM, nil
	}

	// Verify without the lock so signs for other identities don't wait. Two
	// callers that see a new cert at once both verify it, with one result.
	v, err := s.verify(der)
	if err != nil {
		return nil, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Drop expired certs so the memo doesn't grow without bound.
	now := time.Now()
	for k, e := range s.verified {
		if now.After(e.notAfter) {
			delete(s.verified, k)
		}
	}
	s.verified[string(der)] = v
	return v.certPEM, v.chainPEM, nil
}

// verify chains a leaf certificate to a Fulcio CA in the trusted material and
// checks its embedded SCT, as refresh does for certs from the legacy Fulcio
// API. It returns the PEM-encoded leaf and the PEM-encoded chain above it
// (intermediates, then root), which is what the legacy Fulcio API returns.
func (s *sharedCerts) verify(der []byte) (verifiedCert, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return verifiedCert{}, fmt.Errorf("parsing cert: %w", err)
	}
	if err := cryptoutils.EqualKeys(cert.PublicKey, s.keypair.GetPublicKey()); err != nil {
		return verifiedCert{}, fmt.Errorf("cert does not bind the signing key: %w", err)
	}
	// Check the chain at issuance rather than now, so a signer whose clock
	// runs behind Fulcio's doesn't reject a fresh cert as not yet valid.
	// CachingCertProvider already retires certs nearing expiry.
	chains, err := verify.VerifyLeafCertificate(cert.NotBefore, cert, s.trustedMaterial)
	if err != nil {
		return verifiedCert{}, fmt.Errorf("verifying cert chain: %w", err)
	}
	if err := verify.VerifySignedCertificateTimestamp(chains, 1, s.trustedMaterial); err != nil {
		return verifiedCert{}, fmt.Errorf("verifying SCT: %w", err)
	}
	certPEM, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return verifiedCert{}, err
	}
	chainPEM, err := cryptoutils.MarshalCertificatesToPEM(chains[0][1:])
	if err != nil {
		return verifiedCert{}, err
	}
	return verifiedCert{certPEM: certPEM, chainPEM: chainPEM, notAfter: cert.NotAfter}, nil
}

// keypairSignerVerifier is a signature.SignerVerifier over a sign.Keypair,
// whose private key is not exported.
type keypairSignerVerifier struct {
	signature.Verifier
	keypair sign.Keypair
}

func newKeypairSignerVerifier(keypair sign.Keypair) (*keypairSignerVerifier, error) {
	details, err := signature.GetAlgorithmDetails(keypair.GetSigningAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("getting keypair algorithm: %w", err)
	}
	verifier, err := signature.LoadVerifier(keypair.GetPublicKey(), details.GetHashType())
	if err != nil {
		return nil, fmt.Errorf("loading verifier: %w", err)
	}
	return &keypairSignerVerifier{Verifier: verifier, keypair: keypair}, nil
}

func (k *keypairSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	data, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	sig, _, err := k.keypair.SignData(ctx, data)
	return sig, err
}

func (k *keypairSignerVerifier) PublicKey(...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return k.keypair.GetPublicKey(), nil
}
