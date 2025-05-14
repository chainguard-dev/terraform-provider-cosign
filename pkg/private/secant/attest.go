package secant

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	rekordsse "github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/models/dsse"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/models/intoto"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/rekor"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/tlog"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	ctypes "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"golang.org/x/time/rate"
)

var (
	dsseType   = "dsse"
	intotoType = "intoto"
)

// RekorRateLimiter is used to throttle calls to Rekor when signing or attesting images in order to stay within the rate limits.
// Defaults to a 5 QPS limit.
var RekorRateLimiter = rate.NewLimiter(5.0, 50)

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

// AttestEntity is roughly equivalent to cosign attest.
// It operates on the provided oci.SignedEntity without interacting with the registry.
func AttestEntity(ctx context.Context, se oci.SignedEntity, conflict string, statements []*types.Statement, sv types.CosignerSignerVerifier, rekorClient *client.Rekor, opts ...AttestOption) (oci.SignedEntity, error) {
	attestOpts, err := makeAttestOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("initializing attest options: %w", err)
	}
	digest := statements[0].Digest
	atts, err := se.Attestations()
	if err != nil {
		return nil, fmt.Errorf("fetching attestations: %w", err)
	}

	sigs, err := atts.Get()
	if err != nil {
		return nil, fmt.Errorf("getting attestations: %w", err)
	}

	statements, err = newStatements(statements, sigs, conflict)
	if err != nil {
		return nil, fmt.Errorf("failed to determine new statements: %w", err)
	}

	// If there are no net new statements, we can return the original SignedEntity directly.
	if len(statements) == 0 {
		return se, nil
	}

	if RekorRateLimiter != nil {
		// Wait to ensure we don't hit Rekor rate limits.
		// Wait up front for enough tokens to attest all statements to reduce likelihood of partial failure due to context cancellation.
		if err := RekorRateLimiter.WaitN(ctx, len(statements)); err != nil {
			return nil, fmt.Errorf("waiting for rekor rate limiter: %w", err)
		}
	}
	for _, statement := range statements {
		// Make sure these statements are all for the same subject.
		if digest != statement.Digest {
			return nil, fmt.Errorf("mismatched attestations: %s != %s", digest.String(), statement.Digest.String())
		}

		pae := dsse.PAE(ctypes.IntotoPayloadType, statement.Payload)
		signed, err := sv.SignMessage(bytes.NewReader(pae), options.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("signing pae: %w", err)
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
			return nil, fmt.Errorf("marshaling envelope: %w", err)
		}

		// Use the inner Cosigner to safely generate a valid sig, then graft its values on our attestation.
		sig, err := sv.Cosign(ctx, bytes.NewReader(envelope))
		if err != nil {
			return nil, fmt.Errorf("signing envelope: %w", err)
		}

		cert, err := sig.Cert()
		if err != nil {
			return nil, err
		}

		rawCert, err := cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return nil, err
		}

		chain, err := sig.Chain()
		if err != nil {
			return nil, err
		}

		rawChain, err := cryptoutils.MarshalCertificatesToPEM(chain)
		if err != nil {
			return nil, fmt.Errorf("marshaling chain: %w", err)
		}

		var e models.ProposedEntry
		switch attestOpts.rekorEntryType {
		case intotoType:
			e, err = intoto.Entry(ctx, envelope, rawCert)
			if err != nil {
				return nil, fmt.Errorf("creating intoto entry: %w", err)
			}
		case dsseType:
			e, err = rekordsse.Entry(ctx, envelope, rawCert)
			if err != nil {
				return nil, fmt.Errorf("creating dsse entry: %w", err)
			}
		default:
			return nil, fmt.Errorf("invalid rekor entry type: %q", attestOpts.rekorEntryType)
		}
		entry, err := tlog.Upload(ctx, rekorClient, e)
		if err != nil {
			return nil, fmt.Errorf("uploading to rekor: %w", err)
		}

		bundle := cbundle.EntryToBundle(entry)

		predicateType, err := parsePredicateType(statement.Type)
		if err != nil {
			return nil, err
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
			return nil, err
		}

		signOpts := []mutate.SignOption{}
		if conflict != Append {
			signOpts = append(signOpts, mutate.WithReplaceOp(replacePredicate(predicateType)))
		}

		// Attach the attestation to the entity.
		se, err = mutate.AttachAttestationToEntity(se, att, signOpts...)
		if err != nil {
			return nil, err
		}
	}
	return se, nil
}

// Attest is roughly equivalent to cosign attest.
// The only real implementation of types.CosignerSignerVerifier is fulcio.SignerVerifier.
func Attest(ctx context.Context, conflict string, statements []*types.Statement, sv types.CosignerSignerVerifier, rekorClient *client.Rekor, ropt []remote.Option, opts ...AttestOption) error {
	digest := statements[0].Digest

	// We don't actually need to access the remote entity to attach things to it
	// so we use a placeholder here.
	ropts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}
	se := ociremote.SignedUnknown(digest, ropts...)

	newSE, err := AttestEntity(ctx, se, conflict, statements, sv, rekorClient, opts...)
	if err != nil {
		return fmt.Errorf("attesting: %w", err)
	}

	// If the signed entity hasn't changed, we can skip the write entirely
	if se == newSE {
		return nil
	}
	// Publish the attestations associated with this entity
	return ociremote.WriteAttestations(digest.Repository, newSE, ropts...)
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

// Returns only the statements that we actually need to write.
// This allows us to send less traffic to rekor, which means we throttle less.
func newStatements[S sigsubset](statements []*types.Statement, sigs []S, conflict string) ([]*types.Statement, error) {
	if conflict == Append {
		return statements, nil
	}

	needed := map[string]struct{}{}

	// Group desired statements by predicateType.
	ptToStatements := map[string][]*types.Statement{}
	for _, statement := range statements {
		pt, err := parsePredicateType(statement.Type)
		if err != nil {
			return nil, err
		}

		stmts, ok := ptToStatements[pt]
		if !ok {
			stmts = []*types.Statement{}
		}
		stmts = append(stmts, statement)
		ptToStatements[pt] = stmts
	}

	// Group existing statements by predicateType.
	ptToSigs := map[string][]sigsubset{}
	for _, sig := range sigs {
		pt, err := getPredicateType(sig)
		if err != nil {
			return nil, err
		}

		sigs, ok := ptToSigs[pt]
		if !ok {
			sigs = []sigsubset{}
		}
		sigs = append(sigs, sig)
		ptToSigs[pt] = sigs
	}

	for pt, stmts := range ptToStatements {
		// This is user error giving us multiple predicateTypes because we would overwrite one of them.
		if len(stmts) != 1 {
			return nil, fmt.Errorf("expected 1 statement per predicateType, saw %d for %q", len(stmts), pt)
		}

		stmt := stmts[0]

		// There are no existing statements with this predicateType, so we need to add it,
		// or there are multiple statements with this predicateType, so we want to replace them with one.
		sigs, ok := ptToSigs[pt]
		if !ok || len(sigs) != 1 {
			needed[stmt.Type] = struct{}{}
			continue
		}

		if conflict == Replace {
			needed[stmt.Type] = struct{}{}
			continue
		}

		if conflict != SkipSame {
			return nil, fmt.Errorf("unexpected value for 'conflict': %q", conflict)
		}

		// There is a single existing statement.
		// If the payloadHash is the same, we can skip it, otherwise we want to write the new one.
		sig := sigs[0]
		newHash, _, err := v1.SHA256(bytes.NewReader(stmt.Payload))
		if err != nil {
			return nil, fmt.Errorf("computing statement payloadHash: %w", err)
		}

		bundle, err := sig.Bundle()
		if err != nil {
			return nil, fmt.Errorf("getting sig bundle: %w", err)
		}

		payloadHash, err := rekor.PayloadHash(bundle)
		if err != nil {
			// If we hit this error, it means we are attesting something with an unexpected payload format.
			// We may want to surface a warning and overwrite it because it probably means we switched payload formats.
			// Until then, it means something else (not tf-cosign) added an attestation with a conflicting predicateType,
			// so play it safe and just bail out.
			return nil, fmt.Errorf("getting payloadHash from bundle: %w", err)
		}

		// The new statement is different from the existing one, so we need to replace it.
		if newHash != payloadHash {
			needed[stmt.Type] = struct{}{}
		}
	}

	// This is kinda weird but we do it like this to keep the original order (go maps are random).
	result := []*types.Statement{}
	for _, stmt := range statements {
		if _, ok := needed[stmt.Type]; ok {
			result = append(result, stmt)
		}
	}

	return result, nil
}

type attestOptions struct {
	rekorEntryType string
}

type AttestOption (func(*attestOptions) error)

func makeAttestOptions(opts []AttestOption) (*attestOptions, error) {
	o := &attestOptions{
		rekorEntryType: dsseType,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// WithRekorEntryType overrides the entry type that is uploaded to Rekor.
func WithRekorEntryType(t string) AttestOption {
	return func(o *attestOptions) error {
		if t != dsseType && t != intotoType {
			return fmt.Errorf("invalid rekor entry type %q", t)
		}
		o.rekorEntryType = t
		return nil
	}
}

// A subset of oci.Signature that we use so we can test this more easily.
type sigsubset interface {
	Annotations() (map[string]string, error)
	Payload() ([]byte, error)
	Bundle() (*bundle.RekorBundle, error)
}
