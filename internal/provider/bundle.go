package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// OIDCProvider furnishes OIDC tokens for keyless signing.
type OIDCProvider interface {
	Enabled(ctx context.Context) bool
	Provide(ctx context.Context, audience string) (string, error)
}

// bundleSigner holds the materials needed for the cosign v3 bundle signing path.
// The ephemeral keypair is generated once and reused across all operations.
type bundleSigner struct {
	oidc            OIDCProvider
	signingConfig   *root.SigningConfig
	trustedMaterial root.TrustedMaterial

	once    sync.Once
	keypair sign.Keypair
	initErr error
}

// newBundleSigner loads SigningConfig and TrustedMaterial from TUF.
func newBundleSigner(oidc OIDCProvider) (*bundleSigner, error) {
	sc, err := cosign.SigningConfig()
	if err != nil {
		return nil, fmt.Errorf("loading signing config from TUF: %w", err)
	}
	tr, err := cosign.TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("loading trusted root from TUF: %w", err)
	}
	return &bundleSigner{
		oidc:            oidc,
		signingConfig:   sc,
		trustedMaterial: tr,
	}, nil
}

// init lazily generates the ephemeral keypair exactly once.
func (bs *bundleSigner) init() error {
	bs.once.Do(func() {
		bs.keypair, bs.initErr = sign.NewEphemeralKeypair(nil)
		if bs.initErr != nil {
			bs.initErr = fmt.Errorf("generating ephemeral keypair: %w", bs.initErr)
		}
	})
	return bs.initErr
}

// signContent creates a protobuf bundle by signing the given content.
func (bs *bundleSigner) signContent(ctx context.Context, content sign.Content) ([]byte, error) {
	if err := bs.init(); err != nil {
		return nil, err
	}

	idToken, err := bs.oidc.Provide(ctx, "sigstore")
	if err != nil {
		return nil, fmt.Errorf("retrieving ID token: %w", err)
	}

	bundle, err := cbundle.SignData(ctx, content, bs.keypair, idToken, nil, bs.signingConfig, bs.trustedMaterial, cbundle.SignOptions{})
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}
	return bundle, nil
}

// signBundle signs container images using the cosign v3 bundle format
// and writes them as OCI referrers.
func signBundle(ctx context.Context, annotations map[string]any, signer *bundleSigner, imgs []name.Digest, ropt []remote.Option) error {
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

		bundleBytes, err := signer.signContent(ctx, content)
		if err != nil {
			return fmt.Errorf("signing bundle for %q: %w", digest.String(), err)
		}

		if err := ociremote.WriteAttestationNewBundleFormat(digest, bundleBytes, ctypes.CosignSignPredicateType, opts...); err != nil {
			return fmt.Errorf("writing sign bundle for %q: %w", digest.String(), err)
		}
	}

	return nil
}

// attestStatement holds the data needed to write a single attestation bundle.
type attestStatement struct {
	Digest  name.Digest
	Type    string
	Payload []byte
}

// newAttestStatement generates an in-toto statement for use in attestBundle.
func newAttestStatement(digest name.Digest, predicate io.Reader, ptype string) (*attestStatement, error) {
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, err
	}

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      ptype,
		Digest:    h.Hex,
		Repo:      digest.Repository.String(),
	})
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return nil, fmt.Errorf("marshaling statement: %w", err)
	}

	return &attestStatement{
		Digest:  digest,
		Type:    ptype,
		Payload: payload,
	}, nil
}

var predicateTypeMap = map[string]string{
	"custom":         "https://cosign.sigstore.dev/attestation/v1",
	"slsaprovenance": "https://slsa.dev/provenance/v0.2",
	"spdx":           "https://spdx.dev/Document",
	"spdxjson":       "https://spdx.dev/Document",
	"cyclonedx":      "https://cyclonedx.org/bom",
	"link":           "https://in-toto.io/Link/v1",
	"vuln":           "https://cosign.sigstore.dev/attestation/vuln/v1",
}

func parsePredicateType(t string) (string, error) {
	uri, ok := predicateTypeMap[t]
	if !ok {
		if _, err := url.ParseRequestURI(t); err != nil {
			return "", fmt.Errorf("invalid predicate type: %s", t)
		}
		uri = t
	}
	return uri, nil
}

// attestBundle creates attestations using the cosign v3 bundle format
// and writes them as OCI referrers.
func attestBundle(ctx context.Context, statements []*attestStatement, signer *bundleSigner, ropt []remote.Option) error {
	if len(statements) == 0 {
		return nil
	}

	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	for _, stmt := range statements {
		content := &sign.DSSEData{
			Data:        stmt.Payload,
			PayloadType: ctypes.IntotoPayloadType,
		}

		bundleBytes, err := signer.signContent(ctx, content)
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
