package secant

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/chainguard-dev/terraform-provider-cosign/internal/secant/models/intoto"
	"github.com/chainguard-dev/terraform-provider-cosign/internal/secant/tlog"
	"github.com/chainguard-dev/terraform-provider-cosign/internal/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	ctypes "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// NewStatement generates a statement for use in Attest.
func NewStatement(digest name.Digest, predicate io.Reader, ptype string) (*types.Statement, error) {
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

	return &types.Statement{
		Digest:  digest,
		Type:    ptype,
		Payload: payload,
	}, nil
}

// Attest is roughly equivalent to cosign attest.
// The only real implementation of types.CosignerSignerVerifier is fulcio.SignerVerifier.
func Attest(ctx context.Context, statements []*types.Statement, sv types.CosignerSignerVerifier, rekorClient *client.Rekor, ropt []remote.Option) error {
	digest := statements[0].Digest

	// We don't actually need to access the remote entity to attach things to it
	// so we use a placeholder here.
	se := ociremote.SignedUnknown(digest)

	// We use a dupe detector that always verifies because we always want to replace
	// things with a matching predicate type.
	dd := cremote.NewDupeDetector(&alwaysVerifier{})

	for _, statement := range statements {
		// Make sure these statements are all for the same subject.
		if digest != statement.Digest {
			return fmt.Errorf("mismatched attestations: %s != %s", digest.String(), statement.Digest.String())
		}

		pae := dsse.PAE(ctypes.IntotoPayloadType, statement.Payload)
		signed, err := sv.SignMessage(bytes.NewReader(pae), options.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("signing pae: %w", err)
		}

		env := dsse.Envelope{
			PayloadType: ctypes.IntotoPayloadType,
			Payload:     base64.StdEncoding.EncodeToString(statement.Payload),
			Signatures: []dsse.Signature{
				{
					Sig: base64.StdEncoding.EncodeToString(signed),
				},
			},
		}

		envelope, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("marshaling envelope: %w", err)
		}

		// Use the inner Cosigner to safely generate a valid sig, then graft its values on our attestation.
		sig, err := sv.Cosign(ctx, bytes.NewReader(envelope))
		if err != nil {
			return fmt.Errorf("signing envelope: %w", err)
		}

		cert, err := sig.Cert()
		if err != nil {
			return err
		}

		rawCert, err := cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return err
		}

		chain, err := sig.Chain()
		if err != nil {
			return err
		}

		rawChain, err := cryptoutils.MarshalCertificatesToPEM(chain)
		if err != nil {
			return fmt.Errorf("marshaling chain: %w", err)
		}

		e, err := intoto.Entry(ctx, envelope, rawCert)
		if err != nil {
			return fmt.Errorf("creating intoto entry: %w", err)
		}

		entry, err := tlog.Upload(ctx, rekorClient, e)
		if err != nil {
			return fmt.Errorf("uploading to rekor: %w", err)
		}

		bundle := cbundle.EntryToBundle(entry)

		predicateType, err := parsePredicateType(statement.Type)
		if err != nil {
			return err
		}

		opts := []static.Option{
			static.WithCertChain(rawCert, rawChain),
			static.WithBundle(bundle),
			static.WithLayerMediaType(ctypes.DssePayloadType),
			static.WithAnnotations(map[string]string{
				"predicateType": predicateType,
			}),
		}

		att, err := static.NewAttestation(envelope, opts...)
		if err != nil {
			return err
		}

		signOpts := []mutate.SignOption{
			mutate.WithDupeDetector(dd),
			mutate.WithReplaceOp(cremote.NewReplaceOp(predicateType)),
		}

		// Attach the attestation to the entity.
		se, err = mutate.AttachAttestationToEntity(se, att, signOpts...)
		if err != nil {
			return err
		}
	}

	// Publish the attestations associated with this entity
	ropts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}
	return ociremote.WriteAttestations(digest.Repository, se, ropts...)
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

type alwaysVerifier struct{}

// This only exists to satisfy cosign interface jungle.
func (av *alwaysVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	panic("this should not get called ever")
}

// This always verifies.
func (av *alwaysVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	return nil
}
