package fulcio

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	// The deprecated TUF client is used deliberately: it is the client callers
	// configure via tuf.Initialize (e.g. to point at a custom mirror), and it
	// is what cosign.GetCTLogPubs reads from, so the trusted_root.json target
	// must come from the same source.
	"github.com/sigstore/sigstore/pkg/tuf" //nolint:staticcheck
	"golang.org/x/oauth2"
)

var _ types.CosignerSignerVerifier = (*SignerVerifier)(nil)

// OIDCProvider is what providers need to implement to participate in furnishing OIDC tokens.
type OIDCProvider interface {
	// Enabled returns true if the provider is enabled.
	Enabled(ctx context.Context) bool

	// Provide returns an OIDC token scoped to the provided audience.
	Provide(ctx context.Context, audience string) (string, error)
}

// SignerVerifier implements types.CosignerSignerVerifier using "keyless" signatures.
// If its signing certificate expires, it will refresh it by requesting a new cert from fulcio
// using the same key.
type SignerVerifier struct {
	inner        signature.SignerVerifier
	provider     OIDCProvider
	fulcioClient api.LegacyClient

	// Protects these fields from mutating from refresh().
	sync.Mutex
	cert    *x509.Certificate
	certPEM []byte
	chain   []byte
	sct     []byte
}

// NewSigner returns a "keyless" fulcio signer.
func NewSigner(provider OIDCProvider, fulcioClient api.LegacyClient) (*SignerVerifier, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}

	inner, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	sv := &SignerVerifier{
		inner:        inner,
		provider:     provider,
		fulcioClient: fulcioClient,
	}

	return sv, nil
}

func (sv *SignerVerifier) refresh(ctx context.Context) error {
	idToken, err := sv.provider.Provide(ctx, "sigstore")
	if err != nil {
		return err
	}

	flow := &oauthflow.StaticTokenGetter{RawToken: idToken}
	tok, err := flow.GetIDToken(nil, oauth2.Config{})
	if err != nil {
		return err
	}

	publicKey, err := sv.inner.PublicKey()
	if err != nil {
		return err
	}
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return err
	}

	// Sign the email address as part of the request
	proof, err := sv.inner.SignMessage(strings.NewReader(tok.Subject))
	if err != nil {
		return err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Content: pubBytes,
		},
		SignedEmailAddress: proof,
	}

	resp, err := sv.fulcioClient.SigningCert(cr, tok.RawString)
	if err != nil {
		return fmt.Errorf("retrieving cert: %w", err)
	}

	// Grab the PublicKeys for the CTFE, either from tuf or env.
	pubKeys, err := getCTLogPubs(ctx)
	if err != nil {
		return fmt.Errorf("getting CTFE public keys: %w", err)
	}

	// verify the sct
	if err := cosign.VerifySCT(ctx, resp.CertPEM, resp.ChainPEM, resp.SCT, pubKeys); err != nil {
		return fmt.Errorf("verifying SCT: %w", err)
	}

	cert, err := x509util.CertificateFromPEM(resp.CertPEM)
	if err != nil {
		return fmt.Errorf("parsing cert PEM: %w", err)
	}

	sv.cert = cert
	sv.certPEM = resp.CertPEM
	sv.chain = resp.ChainPEM
	sv.sct = resp.SCT

	return nil
}

// getCTLogPubs returns the CT log public keys to verify SCTs against.
//
// cosign.GetCTLogPubs reads only the individual ctfe*.pub TUF targets, which
// sigstore treats as deprecated: keys for newer CT logs can be published only
// inside the trusted_root.json target (the staging instance's
// log2026-1.us-east4 log is one, see sigstore/root-signing-staging#434). An
// SCT issued by such a log fails verification with "ctfe public key not found
// for payload" if only the legacy targets are loaded, so the CT log keys from
// trusted_root.json are merged in. Keys are indexed by log ID, so keys
// present in both sources dedupe.
func getCTLogPubs(ctx context.Context) (*cosign.TrustedTransparencyLogPubKeys, error) {
	// An explicit key file overrides TUF entirely; keep cosign's behavior.
	if env.Getenv(env.VariableSigstoreCTLogPublicKeyFile) != "" {
		return cosign.GetCTLogPubs(ctx)
	}

	pubKeys := cosign.NewTrustedTransparencyLogPubKeys()

	legacy, legacyErr := cosign.GetCTLogPubs(ctx)
	if legacyErr == nil {
		maps.Copy(pubKeys.Keys, legacy.Keys)
	}

	trustedRootErr := func() error {
		tufClient, err := tuf.NewFromEnv(ctx)
		if err != nil {
			return err
		}
		b, err := tufClient.GetTarget("trusted_root.json")
		if err != nil {
			return err
		}
		return addTrustedRootCTLogKeys(&pubKeys, b)
	}()

	// Either source alone can be incomplete or absent (older TUF repos have no
	// trusted_root.json target), so fail only when both yielded nothing.
	if len(pubKeys.Keys) == 0 {
		return nil, errors.Join(errors.New("no CT log public keys found"), legacyErr, trustedRootErr)
	}
	return &pubKeys, nil
}

// addTrustedRootCTLogKeys adds the CT log keys from a serialized
// trusted_root.json to pubKeys.
func addTrustedRootCTLogKeys(pubKeys *cosign.TrustedTransparencyLogPubKeys, trustedRootJSON []byte) error {
	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return fmt.Errorf("parsing trusted root: %w", err)
	}
	for _, ctlog := range tr.CTLogs() {
		pem, err := cryptoutils.MarshalPublicKeyToPEM(ctlog.PublicKey)
		if err != nil {
			return fmt.Errorf("marshaling CT log key: %w", err)
		}
		if err := pubKeys.AddTransparencyLogPubKey(pem, tuf.Active); err != nil {
			return fmt.Errorf("adding CT log key: %w", err)
		}
	}
	return nil
}

func (sv *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	return sv.inner.SignMessage(message, opts...)
}

func (sv *SignerVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	return sv.inner.VerifySignature(signature, message, opts...)
}

func (sv *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return sv.inner.PublicKey(opts...)
}

func (sv *SignerVerifier) Cosign(ctx context.Context, payload io.Reader) (oci.Signature, error) {
	payloadBytes, err := io.ReadAll(payload)
	if err != nil {
		return nil, err
	}
	signed, err := sv.inner.SignMessage(bytes.NewReader(payloadBytes), options.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	sv.Lock()
	defer sv.Unlock()

	// If this is our first cert or the cert is expired, we need to hit fulcio.
	// Add 30 seconds of buffer to account for clock skew (gitsign does the same).
	if sv.cert == nil || time.Now().Add(time.Second*30).After(sv.cert.NotAfter) {
		if err := sv.refresh(ctx); err != nil {
			return nil, fmt.Errorf("refreshing fulcio cert: %w", err)
		}
	}

	sig, err := static.NewSignature(payloadBytes, base64.StdEncoding.EncodeToString(signed), static.WithCertChain(sv.certPEM, sv.chain))
	if err != nil {
		return nil, err
	}

	return sig, nil
}
