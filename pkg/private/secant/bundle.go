package secant

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/fulcio"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// BundleSigner holds the materials needed for the v3 "bundle" signing path.
// The ephemeral keypair is generated once and reused across all operations.
// The OIDC token is fetched via the OIDCProvider on each sign; the provider
// handles caching with a TTL so that back-to-back calls share one auth
// prompt while long-separated calls get a fresh token.
type BundleSigner struct {
	oidc            fulcio.OIDCProvider
	signingConfig   *root.SigningConfig
	trustedMaterial root.TrustedMaterial

	once    sync.Once
	keypair sign.Keypair
	initErr error
}

// NewBundleSigner loads SigningConfig and TrustedMaterial from TUF and returns
// a BundleSigner that will lazily generate a keypair on first use.
func NewBundleSigner(oidc fulcio.OIDCProvider) (*BundleSigner, error) {
	sc, err := cosign.SigningConfig()
	if err != nil {
		return nil, fmt.Errorf("loading signing config from TUF: %w", err)
	}
	tr, err := cosign.TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("loading trusted root from TUF: %w", err)
	}
	return &BundleSigner{
		oidc:            oidc,
		signingConfig:   sc,
		trustedMaterial: tr,
	}, nil
}

// init lazily generates the ephemeral keypair exactly once.
func (bs *BundleSigner) init() error {
	bs.once.Do(func() {
		bs.keypair, bs.initErr = sign.NewEphemeralKeypair(nil)
		if bs.initErr != nil {
			bs.initErr = fmt.Errorf("generating ephemeral keypair: %w", bs.initErr)
		}
	})
	return bs.initErr
}

// SignContent creates a protobuf bundle by signing the given content.
func (bs *BundleSigner) SignContent(ctx context.Context, content sign.Content) ([]byte, error) {
	if err := bs.init(); err != nil {
		return nil, err
	}

	idToken, err := bs.oidc.Provide(ctx, "sigstore")
	if err != nil {
		return nil, fmt.Errorf("retrieving ID token: %w", err)
	}

	signOpts := cbundle.SignOptions{}
	bundle, err := cbundle.SignData(ctx, content, bs.keypair, idToken, nil, bs.signingConfig, bs.trustedMaterial, signOpts)
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}
	return bundle, nil
}

// SignBundle signs container images using the v3 bundle format and writes them as OCI referrers.
// The BundleSigner's cached credentials are reused across all images.
func SignBundle(ctx context.Context, annotations map[string]any, signer *BundleSigner, imgs []name.Digest, ropt []remote.Option) error {
	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	for _, digest := range imgs {
		digestParts := strings.Split(digest.DigestStr(), ":")
		if len(digestParts) != 2 {
			return fmt.Errorf("unable to parse digest %s", digest.DigestStr())
		}

		annoStruct, _ := structpb.NewStruct(annotations)
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

// AttestBundle creates attestations using the v3 bundle format and writes them as OCI referrers.
// The BundleSigner's cached credentials are reused across all statements.
func AttestBundle(ctx context.Context, statements []*types.Statement, signer *BundleSigner, ropt []remote.Option, opts ...AttestOption) error {
	if len(statements) == 0 {
		return nil
	}

	attestOpts, err := makeAttestOptions(opts)
	if err != nil {
		return fmt.Errorf("initializing attest options: %w", err)
	}
	_ = attestOpts // rekorEntryType is not used in the bundle path

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
