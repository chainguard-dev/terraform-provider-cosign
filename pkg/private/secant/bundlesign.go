package secant

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/fulcio"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// BundleSigner holds the materials needed for the cosign v3 bundle signing path.
// The ephemeral keypair is generated once and reused across all operations.
// Fulcio certificates are cached and refreshed when nearing expiry.
type BundleSigner struct {
	oidc            fulcio.OIDCProvider
	signingConfig   *root.SigningConfig
	trustedMaterial root.TrustedMaterial
	keypair         sign.Keypair

	mu      sync.Mutex
	certPEM []byte            // Cached PEM-encoded Fulcio certificate
	cert    *x509.Certificate // Parsed cert for expiry checking
}

// NewBundleSigner loads SigningConfig and TrustedMaterial from TUF and generates
// an ephemeral keypair for signing.
func NewBundleSigner(oidc fulcio.OIDCProvider) (*BundleSigner, error) {
	sc, err := cosign.SigningConfig()
	if err != nil {
		return nil, fmt.Errorf("loading signing config from TUF: %w", err)
	}
	tr, err := cosign.TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("loading trusted root from TUF: %w", err)
	}
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	return &BundleSigner{
		oidc:            oidc,
		signingConfig:   sc,
		trustedMaterial: tr,
		keypair:         keypair,
	}, nil
}

// signWithIDToken signs content via cbundle.SignData using an OIDC token,
// which internally fetches a new Fulcio certificate. The cert is then
// extracted from the resulting bundle and cached for future calls.
// Must be called with bs.mu held.
func (bs *BundleSigner) signWithIDToken(ctx context.Context, content sign.Content) ([]byte, error) {
	idToken, err := bs.oidc.Provide(ctx, "sigstore")
	if err != nil {
		return nil, fmt.Errorf("retrieving ID token: %w", err)
	}

	bundleBytes, err := cbundle.SignData(ctx, content, bs.keypair, idToken, nil, bs.signingConfig, bs.trustedMaterial, cbundle.SignOptions{})
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}

	if err := bs.cacheCertFromBundle(bundleBytes); err != nil {
		return nil, fmt.Errorf("caching cert from bundle: %w", err)
	}

	return bundleBytes, nil
}

// cacheCertFromBundle extracts the signing certificate from a serialized
// protobuf bundle and caches it for reuse on subsequent sign operations.
func (bs *BundleSigner) cacheCertFromBundle(bundleBytes []byte) error {
	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return fmt.Errorf("unmarshaling bundle: %w", err)
	}

	cert := bundle.GetVerificationMaterial().GetCertificate()
	if cert == nil {
		return fmt.Errorf("bundle contains no certificate")
	}
	derBytes := cert.GetRawBytes()

	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("parsing certificate from bundle: %w", err)
	}

	bs.certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	bs.cert = parsed
	return nil
}

// certNeedsRefresh reports whether the cached cert is missing or nearing
// expiry (within 30 seconds, matching the legacy fulcio path).
func (bs *BundleSigner) certNeedsRefresh() bool {
	return bs.cert == nil || time.Now().Add(30*time.Second).After(bs.cert.NotAfter)
}

// SignContent creates a protobuf bundle by signing the given content.
// On first call (or when the cached cert is nearing expiry), delegates to
// cbundle.SignData with an OIDC token, which fetches a new Fulcio cert
// internally. The cert is extracted from the bundle and cached so that
// subsequent calls pass it directly, skipping Fulcio entirely.
func (bs *BundleSigner) SignContent(ctx context.Context, content sign.Content) ([]byte, error) {
	// Lock scope is deliberately split: we hold the mutex across a cert
	// refresh so concurrent callers coalesce onto a single Fulcio fetch,
	// but release it before the steady-state sign so cached-cert signs
	// run in parallel.
	bs.mu.Lock()

	if bs.certNeedsRefresh() {
		// Refresh path: keep the lock held through signWithIDToken so
		// other goroutines observing certNeedsRefresh() block here
		// instead of each issuing their own OIDC + Fulcio round-trip.
		bundleBytes, err := bs.signWithIDToken(ctx, content)
		bs.mu.Unlock()
		return bundleBytes, err
	}

	// Snapshot the cached PEM under the lock so a concurrent refresh
	// can't swap bs.certPEM out from under us mid-sign.
	certPEM := bs.certPEM
	bs.mu.Unlock()

	// Steady state: sign with the cached cert, skipping Fulcio. Safe to
	// run unlocked because certPEM is a local copy and the keypair /
	// signingConfig / trustedMaterial fields are immutable after init.
	bundle, err := cbundle.SignData(ctx, content, bs.keypair, "", certPEM, bs.signingConfig, bs.trustedMaterial, cbundle.SignOptions{})
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}
	return bundle, nil
}

// SignBundle signs container images using the cosign v3 bundle format
// and writes them as OCI referrers.
func SignBundle(ctx context.Context, annotations map[string]any, signer *BundleSigner, imgs []name.Digest, ropt []remote.Option) error {
	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	for _, digest := range imgs {
		digestParts := strings.Split(digest.DigestStr(), ":")
		if len(digestParts) != 2 {
			return fmt.Errorf("unable to parse digest %s", digest.DigestStr())
		}

		annoStruct, err := structpb.NewStruct(annotations)
		if err != nil {
			return fmt.Errorf("converting annotations to protobuf struct: %w", err)
		}
		subject := intotov1.ResourceDescriptor{
			Digest:      map[string]string{digestParts[0]: digestParts[1]},
			Annotations: annoStruct,
		}

		statement := &intotov1.Statement{
			Type:          intotov1.StatementTypeUri,
			Subject:       []*intotov1.ResourceDescriptor{&subject},
			PredicateType: ctypes.CosignSignPredicateType,
			Predicate:     &structpb.Struct{},
		}

		payload, err := protojson.Marshal(statement)
		if err != nil {
			return fmt.Errorf("marshaling statement: %w", err)
		}

		content := &sign.DSSEData{
			Data:        payload,
			PayloadType: ctypes.IntotoPayloadType,
		}

		bundleBytes, err := signer.SignContent(ctx, content)
		if err != nil {
			return fmt.Errorf("signing bundle for %q: %w", digest.String(), err)
		}

		if err := ociremote.WriteAttestationNewBundleFormat(digest, bundleBytes, ctypes.CosignSignPredicateType, opts...); err != nil {
			return fmt.Errorf("writing sign bundle for %q: %w", digest.String(), err)
		}
	}

	return nil
}

// AttestBundle creates attestations using the cosign v3 bundle format
// and writes them as OCI referrers.
func AttestBundle(ctx context.Context, statements []*types.Statement, signer *BundleSigner, ropt []remote.Option) error {
	if len(statements) == 0 {
		return nil
	}

	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	for _, stmt := range statements {
		content := &sign.DSSEData{
			Data:        stmt.Payload,
			PayloadType: ctypes.IntotoPayloadType,
		}

		bundleBytes, err := signer.SignContent(ctx, content)
		if err != nil {
			return fmt.Errorf("signing attestation bundle for %q: %w", stmt.Digest.String(), err)
		}

		predicateType, err := parsePredicateType(stmt.Type)
		if err != nil {
			return err
		}

		if err := ociremote.WriteAttestationNewBundleFormat(stmt.Digest, bundleBytes, predicateType, ociOpts...); err != nil {
			return fmt.Errorf("writing attestation bundle for %q: %w", stmt.Digest.String(), err)
		}
	}

	return nil
}
