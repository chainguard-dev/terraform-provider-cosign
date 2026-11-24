package secant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/fulcio"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/walk"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// BundleSigner holds the materials needed for the cosign v3 bundle signing path.
// The ephemeral keypair is generated once and reused across all operations.
// Fulcio certificates come from a sign.CertificateProvider, by default a
// fulcio.CachingCertProvider that caches them per OIDC identity until they
// near expiry. Every sign asks the OIDC provider for a token, so a
// BundleSigner whose provider returns tokens for different identities (e.g.
// per-org scopes picked from the request context) always signs with a cert for
// the current request's identity.
type BundleSigner struct {
	oidc            fulcio.OIDCProvider
	signingConfig   *root.SigningConfig
	trustedMaterial root.TrustedMaterial
	keypair         sign.Keypair
	certs           sign.CertificateProvider
	transport       http.RoundTripper
}

// BundleSignerOption customizes a BundleSigner at construction.
type BundleSignerOption func(*bundleSignerConfig)

type bundleSignerConfig struct {
	signingConfig   *root.SigningConfig
	trustedMaterial root.TrustedMaterial
	certs           sign.CertificateProvider
	transport       http.RoundTripper
}

// WithSigningConfig overrides the SigningConfig that would otherwise be loaded
// from the public TUF root. Useful when the desired Fulcio/Rekor topology is
// not yet reflected in TUF (e.g. piloting a Rekor v2 instance).
func WithSigningConfig(sc *root.SigningConfig) BundleSignerOption {
	return func(c *bundleSignerConfig) { c.signingConfig = sc }
}

// WithTrustedMaterial overrides the TrustedRoot that would otherwise be loaded
// from the public TUF root. Primarily a test seam.
func WithTrustedMaterial(tm root.TrustedMaterial) BundleSignerOption {
	return func(c *bundleSignerConfig) { c.trustedMaterial = tm }
}

// WithCertificateProvider overrides where signing certificates come from. It
// is called on every sign with the BundleSigner's keypair and the current ID
// token, so it must cache certificates itself and return one issued to that
// token's identity. The default is a fulcio.CachingCertProvider over the
// Fulcio instance in the SigningConfig.
func WithCertificateProvider(p sign.CertificateProvider) BundleSignerOption {
	return func(c *bundleSignerConfig) { c.certs = p }
}

// WithTransport sets the transport for the Fulcio, timestamp authority and
// Rekor v2 requests made while signing, in place of http.DefaultTransport.
// Each request carries the context passed to the signing call, so a tracing
// transport records it under the caller's span. A certificate provider set
// with WithCertificateProvider makes its own requests and ignores this.
func WithTransport(rt http.RoundTripper) BundleSignerOption {
	return func(c *bundleSignerConfig) { c.transport = rt }
}

// NewBundleSigner loads SigningConfig and TrustedMaterial from TUF (unless
// overridden via options) and generates an ephemeral keypair for signing.
func NewBundleSigner(oidc fulcio.OIDCProvider, opts ...BundleSignerOption) (*BundleSigner, error) {
	cfg := &bundleSignerConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.signingConfig == nil {
		sc, err := cosign.SigningConfig()
		if err != nil {
			return nil, fmt.Errorf("loading signing config from TUF: %w", err)
		}
		cfg.signingConfig = sc
	}
	if cfg.trustedMaterial == nil {
		tr, err := cosign.TrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("loading trusted root from TUF: %w", err)
		}
		cfg.trustedMaterial = tr
	}
	if cfg.certs == nil {
		inner, err := fulcio.NewCertProvider(cfg.signingConfig, cfg.transport)
		if err != nil {
			return nil, fmt.Errorf("creating fulcio client: %w", err)
		}
		cfg.certs = fulcio.NewCachingCertProvider(inner)
	}
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	return &BundleSigner{
		oidc:            oidc,
		signingConfig:   cfg.signingConfig,
		trustedMaterial: cfg.trustedMaterial,
		keypair:         keypair,
		certs:           cfg.certs,
		transport:       cfg.transport,
	}, nil
}

// LegacySigner returns a legacy-format signer that shares this BundleSigner's
// keypair, certificate provider and OIDC provider, so a caller signing both
// formats gets one Fulcio certificate per identity and expiry window instead
// of one per format. Its signatures carry the same certificate as this
// BundleSigner's bundles, with the chain built from the BundleSigner's
// TrustedMaterial (see fulcio.NewSharedSigner).
func (bs *BundleSigner) LegacySigner() (*fulcio.SignerVerifier, error) {
	return fulcio.NewSharedSigner(bs.oidc, bs.keypair, bs.certs, bs.trustedMaterial)
}

// SignContent creates a protobuf bundle by signing the given content with a
// certificate for the identity of the OIDC provider's current token. The
// certificate provider caches certificates, so steady-state signs skip Fulcio.
func (bs *BundleSigner) SignContent(ctx context.Context, content sign.Content) ([]byte, error) {
	// Every SignContent ends in one transparency-log upload, and the
	// Rekor v2 write client does not retry a 429 — gate it through the
	// same limiter as the legacy paths.
	if RekorRateLimiter != nil {
		if err := RekorRateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("waiting for rekor rate limiter: %w", err)
		}
	}

	// The provider may return tokens for different identities depending on
	// ctx, so the token is fetched per call. Providers cache their tokens,
	// so this is cheap.
	idToken, err := bs.oidc.Provide(ctx, "sigstore")
	if err != nil {
		return nil, fmt.Errorf("retrieving ID token: %w", err)
	}

	bundle, err := bs.signData(ctx, content, idToken)
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}
	return bundle, nil
}

// contentSigner is the part of BundleSigner that the bundle signing paths
// consume — the seam that lets tests drive the walk and the per-digest write
// without Fulcio.
type contentSigner interface {
	SignContent(ctx context.Context, content sign.Content) ([]byte, error)
}

// SignBundle signs container images using the cosign v3 bundle format
// and writes them as OCI referrers. Like the legacy Sign, it signs each
// image and its constituent manifests transitively: an image index and every
// child manifest each get their own sign-predicate bundle referrer, so
// arch-pinned digests verify the same as the index. conflict matches the
// semantics of Sign: APPEND (or empty) always writes, SKIPSAME skips when an
// existing referrer has an identical payload, REPLACE deletes existing
// referrers with matching predicate type before writing.
//
// SignBundle fetches each image to walk it, so every digest in imgs must
// already exist in the registry. Callers that enumerate manifests themselves,
// or that sign concurrently with a push, use SignBundleDigest.
func SignBundle(ctx context.Context, conflict string, annotations map[string]any, signer *BundleSigner, imgs []name.Digest, ropt []remote.Option) error {
	return signBundle(ctx, conflict, annotations, signer, imgs, ropt)
}

func signBundle(ctx context.Context, conflict string, annotations map[string]any, signer contentSigner, imgs []name.Digest, ropt []remote.Option) error {
	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	for _, ref := range imgs {
		se, err := ociremote.SignedEntity(ref, opts...)
		if err != nil {
			return fmt.Errorf("accessing entity: %w", err)
		}

		if err := walk.SignedEntity(ctx, se, func(ctx context.Context, se oci.SignedEntity) error {
			// The walk yields oci.SignedImage or oci.SignedImageIndex, both
			// Describable, so the referrer subject comes from what the walk
			// already fetched rather than a HEAD per entity.
			describable, ok := se.(partial.Describable)
			if !ok {
				return fmt.Errorf("unexpected signed entity type %T", se)
			}
			subjectDesc, err := partial.Descriptor(describable)
			if err != nil {
				return fmt.Errorf("describing entity: %w", err)
			}
			return signBundleDigest(ctx, conflict, annotations, signer, ref.Context().Digest(subjectDesc.Digest.String()), subjectDesc, ropt, opts)
		}); err != nil {
			return fmt.Errorf("recursively signing: %w", err)
		}
	}

	return nil
}

// SignBundleDigest signs exactly the given digest with a sign-predicate
// bundle written as an OCI referrer, without recursing into an index's
// children. Because the subject manifest is never fetched — the referrer's
// subject descriptor is synthesized from the digest — the digest does not
// need to exist in the registry yet. conflict has the same semantics as
// SignBundle.
func SignBundleDigest(ctx context.Context, conflict string, annotations map[string]any, signer *BundleSigner, digest name.Digest, ropt []remote.Option) error {
	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}
	return signBundleDigest(ctx, conflict, annotations, signer, digest, nil, ropt, opts)
}

// SignBundleDigests signs the given digests with a single sign-predicate
// statement that names all of them as subjects, in the order given, and
// writes the resulting bundle as an OCI referrer of each digest. The whole set
// costs one signature and one transparency-log entry instead of one per
// digest, and the bundle verifies on any of the digests: a verifier accepts an
// in-toto statement when the artifact is among its subjects.
//
// It is meant for digests that are signed together and for the same reason,
// such as an image index and its per-platform manifests. Everyone who can read
// the signature on one digest learns the others.
//
// Like SignBundleDigest it does not recurse into an index's children and never
// fetches the subjects, so they need not exist in the registry yet. conflict
// applies to each digest on its own: with SKIPSAME a digest that already
// carries a sign statement naming it is left alone, even when that statement
// names different siblings (see statementCovers), and nothing is signed when
// that holds for all of them. A single digest behaves exactly like
// SignBundleDigest.
func SignBundleDigests(ctx context.Context, conflict string, annotations map[string]any, signer *BundleSigner, digests []name.Digest, ropt []remote.Option) error {
	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}
	subjects := make([]signSubject, 0, len(digests))
	for _, d := range digests {
		subjects = append(subjects, signSubject{digest: d})
	}
	return signBundleStatement(ctx, conflict, annotations, signer, subjects, ropt, opts)
}

// signSubject is one digest to sign. desc, when non-nil, is used verbatim as
// the referrer's subject descriptor; nil synthesizes a digest-only one.
// Neither reads the subject.
type signSubject struct {
	digest name.Digest
	desc   *v1.Descriptor
}

// signBundleDigest signs exactly one digest with a sign-predicate bundle,
// applying the conflict policy against its existing referrers. subjectDesc,
// when non-nil, is used verbatim as the referrer's subject descriptor; nil
// synthesizes a digest-only one. Neither reads the subject.
func signBundleDigest(ctx context.Context, conflict string, annotations map[string]any, signer contentSigner, digest name.Digest, subjectDesc *v1.Descriptor, ropt []remote.Option, opts []ociremote.Option) error {
	return signBundleStatement(ctx, conflict, annotations, signer, []signSubject{{digest: digest, desc: subjectDesc}}, ropt, opts)
}

// signBundleStatement signs one sign-predicate statement naming every subject
// and writes the bundle as a referrer of each subject that the conflict policy
// says needs it. The statement is signed at most once.
func signBundleStatement(ctx context.Context, conflict string, annotations map[string]any, signer contentSigner, subjects []signSubject, ropt []remote.Option, opts []ociremote.Option) error {
	if len(subjects) == 0 {
		return nil
	}

	annoStruct, err := structpb.NewStruct(annotations)
	if err != nil {
		return fmt.Errorf("converting annotations to protobuf struct: %w", err)
	}

	hashes := make([]v1.Hash, len(subjects))
	descriptors := make([]*intotov1.ResourceDescriptor, len(subjects))
	seen := make(map[string]struct{}, len(subjects))
	for i, s := range subjects {
		h, err := v1.NewHash(s.digest.DigestStr())
		if err != nil {
			return fmt.Errorf("parsing digest %q: %w", s.digest.String(), err)
		}
		if _, ok := seen[s.digest.String()]; ok {
			return fmt.Errorf("digest %q listed more than once", s.digest.String())
		}
		seen[s.digest.String()] = struct{}{}
		hashes[i] = h
		descriptors[i] = &intotov1.ResourceDescriptor{
			Digest:      map[string]string{h.Algorithm: h.Hex},
			Annotations: annoStruct,
		}
	}

	statement := &intotov1.Statement{
		Type:          intotov1.StatementTypeUri,
		Subject:       descriptors,
		PredicateType: ctypes.CosignSignPredicateType,
		Predicate:     &structpb.Struct{},
	}

	payload, err := protojson.Marshal(statement)
	if err != nil {
		return fmt.Errorf("marshaling statement: %w", err)
	}

	// Each subject has its own referrers (and, without the native Referrers
	// API, its own fallback-tag index), so the subjects resolve and are
	// written independently of one another.
	write := make([]bool, len(subjects))
	var resolve errgroup.Group
	for i, s := range subjects {
		resolve.Go(func() error {
			shouldWrite, err := resolveBundleConflict(s.digest, ctypes.CosignSignPredicateType, payload, conflict, ropt, opts)
			if err != nil {
				return fmt.Errorf("resolving conflict for %q: %w", s.digest.String(), err)
			}
			write[i] = shouldWrite
			return nil
		})
	}
	if err := resolve.Wait(); err != nil {
		return err
	}
	if !slices.Contains(write, true) {
		return nil
	}

	content := &sign.DSSEData{
		Data:        payload,
		PayloadType: ctypes.IntotoPayloadType,
	}

	bundleBytes, err := signer.SignContent(ctx, content)
	if err != nil {
		return fmt.Errorf("signing bundle for %s: %w", describeSignSubjects(subjects), err)
	}

	var writes errgroup.Group
	for i, s := range subjects {
		if !write[i] {
			continue
		}
		writes.Go(func() error {
			subjectDesc := s.desc
			if subjectDesc == nil {
				subjectDesc = &v1.Descriptor{Digest: hashes[i]}
			}
			if err := writeBundleReferrer(s.digest, bundleBytes, ctypes.CosignSignPredicateType, subjectDesc, ropt); err != nil {
				return fmt.Errorf("writing sign bundle for %q: %w", s.digest.String(), err)
			}
			return nil
		})
	}
	return writes.Wait()
}

// describeSignSubjects names the subjects of a sign operation for an error.
func describeSignSubjects(subjects []signSubject) string {
	if len(subjects) == 1 {
		return fmt.Sprintf("%q", subjects[0].digest.String())
	}
	return fmt.Sprintf("%q and %d more", subjects[0].digest.String(), len(subjects)-1)
}

// AttestBundle creates attestations using the cosign v3 bundle format
// and writes them as OCI referrers. See SignBundle for conflict semantics.
// Statements may carry a verbatim subject descriptor (Statement.SubjectDescriptor)
// for subjects that are absent from the target repository.
//
// Statements for different subjects that share a byte-identical Payload are one
// multi-subject statement (see NewMultiSubjectStatements): it is signed once
// and the bundle is written as a referrer of each of those subjects.
func AttestBundle(ctx context.Context, conflict string, statements []*types.Statement, signer *BundleSigner, ropt []remote.Option) error {
	return attestBundle(ctx, conflict, statements, signer, ropt)
}

// attestBundle is AttestBundle over the contentSigner seam, so tests can drive
// it without Fulcio or Rekor.
//
// Statements are handled per subject. On a registry without the native
// Referrers API every referrer write for a subject rewrites the same
// client-maintained sha256-<subject> fallback-tag index with an unconditional
// read, modify and write (go-containerregistry does so on each remote.Put of a
// manifest with a subject, and pruneFallbackReferrers does so too), so two
// writers for one subject can drop each other's entries. Different subjects
// share no such state and are handled concurrently. Within a subject only
// signing, which is where the network time goes (TSA and Rekor v2 inside
// sign.Bundle), runs concurrently; see attestBundleSubject. AttestConcurrency
// bounds the signatures in flight across the whole call.
func attestBundle(ctx context.Context, conflict string, statements []*types.Statement, signer contentSigner, ropt []remote.Option) error {
	if len(statements) == 0 {
		return nil
	}

	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	// Group by subject, keeping the order in which each subject first appears.
	var subjects []string
	groups := map[string][]*types.Statement{}
	for _, stmt := range statements {
		key := stmt.Digest.String()
		if _, ok := groups[key]; !ok {
			subjects = append(subjects, key)
		}
		groups[key] = append(groups[key], stmt)
	}

	shared := newSharedSigner(signer, attestConcurrencyLimit())
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(attestConcurrencyLimit())
	for _, key := range subjects {
		g.Go(func() error {
			return attestBundleSubject(gctx, conflict, groups[key], shared, ropt, ociOpts)
		})
	}
	return g.Wait()
}

// sharedSigner signs each distinct payload once for all the subjects of one
// AttestBundle call that carry it, and bounds the signatures in flight.
//
// A payload shared between subjects is a multi-subject statement, which needs
// a single signature (and a single transparency-log entry) however many
// subjects it is attached to. Two statements with the same payload on one
// subject are a different thing — duplicates that APPEND writes separately —
// so signatures are keyed by the payload and by how many times it has already
// occurred within the subject.
type sharedSigner struct {
	inner contentSigner
	sem   chan struct{}

	mu    sync.Mutex
	calls map[sharedSignKey]*sharedSignCall
}

type sharedSignKey struct {
	payload    [sha256.Size]byte
	occurrence int
}

type sharedSignCall struct {
	done   chan struct{}
	bundle []byte
	err    error
}

func newSharedSigner(inner contentSigner, limit int) *sharedSigner {
	return &sharedSigner{
		inner: inner,
		sem:   make(chan struct{}, limit),
		calls: map[sharedSignKey]*sharedSignCall{},
	}
}

// sign returns the bundle for payload, signing it unless another subject's
// statement with the same payload and occurrence already has or is doing so.
func (s *sharedSigner) sign(ctx context.Context, payload []byte, occurrence int) ([]byte, error) {
	key := sharedSignKey{payload: sha256.Sum256(payload), occurrence: occurrence}

	s.mu.Lock()
	call, ok := s.calls[key]
	if !ok {
		call = &sharedSignCall{done: make(chan struct{})}
		s.calls[key] = call
	}
	s.mu.Unlock()

	if ok {
		select {
		case <-call.done:
			return call.bundle, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	defer close(call.done)
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		call.err = ctx.Err()
		return nil, call.err
	}
	call.bundle, call.err = s.inner.SignContent(ctx, &sign.DSSEData{
		Data:        payload,
		PayloadType: ctypes.IntotoPayloadType,
	})
	return call.bundle, call.err
}

// attestBundleSubject attests the statements of one subject in three passes:
// it resolves conflicts one statement at a time against a single listing of
// the subject's referrers, signs the statements that still need writing with
// bounded overlap (see AttestConcurrency), and then writes the referrers one
// at a time in statement order.
func attestBundleSubject(ctx context.Context, conflict string, statements []*types.Statement, signer *sharedSigner, ropt []remote.Option, ociOpts []ociremote.Option) error {
	subject := statements[0].Digest

	predicateTypes := make([]string, len(statements))
	for i, stmt := range statements {
		predicateType, err := parsePredicateType(stmt.Type)
		if err != nil {
			return err
		}
		predicateTypes[i] = predicateType
	}

	write := make([]bool, len(statements))
	switch conflict {
	case "", Append:
		for i := range write {
			write[i] = true
		}
	case SkipSame, Replace:
		// Two statements of one predicate type would have to resolve against
		// each other's write, which a single listing cannot see. The legacy
		// path rejects this too (see newStatements).
		seen := map[string]int{}
		for _, predicateType := range predicateTypes {
			seen[predicateType]++
		}
		for _, predicateType := range predicateTypes {
			if n := seen[predicateType]; n != 1 {
				return fmt.Errorf("expected 1 statement per predicateType, saw %d for %q", n, predicateType)
			}
		}

		existing, err := bundleReferrersByPredicateType(subject, ociOpts, ropt)
		if err != nil {
			return fmt.Errorf("resolving conflict for %q: %w", subject.String(), err)
		}
		for i, stmt := range statements {
			shouldWrite, deleted, err := supersedeBundleReferrers(subject, stmt.Payload, conflict, existing[predicateTypes[i]], ropt)
			if err != nil {
				return fmt.Errorf("resolving conflict for %q: %w", subject.String(), err)
			}
			write[i] = shouldWrite
			// Drop this statement's deletions from a fallback-tag index now
			// (see resolveBundleConflict for why), not once after the loop:
			// if a later statement fails to resolve, the index must not be
			// left pointing at manifests that are already gone, or a retry
			// would re-commit those dangling entries and be rejected.
			if err := pruneFallbackReferrers(subject, deleted, ropt); err != nil {
				return fmt.Errorf("pruning fallback referrers for %q: %w", subject.String(), err)
			}
		}
	default:
		return fmt.Errorf("unknown conflict mode: %q", conflict)
	}

	// Sign with bounded overlap. BundleSigner supports concurrent callers. A
	// payload that another subject of this call carries too is signed once
	// between them (see sharedSigner).
	bundles := make([][]byte, len(statements))
	occurrences := map[string]int{}
	g, gctx := errgroup.WithContext(ctx)
	for i, stmt := range statements {
		occurrence := occurrences[string(stmt.Payload)]
		occurrences[string(stmt.Payload)]++
		if !write[i] {
			continue
		}
		g.Go(func() error {
			bundleBytes, err := signer.sign(gctx, stmt.Payload, occurrence)
			if err != nil {
				return fmt.Errorf("signing attestation bundle for %q: %w", stmt.Digest.String(), err)
			}
			bundles[i] = bundleBytes
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	// Write one at a time: each write may rewrite the subject's fallback index.
	for i, stmt := range statements {
		if !write[i] {
			continue
		}
		if err := writeBundleReferrer(stmt.Digest, bundles[i], predicateTypes[i], stmt.SubjectDescriptor, ropt); err != nil {
			return fmt.Errorf("writing attestation bundle for %q: %w", stmt.Digest.String(), err)
		}
	}
	return nil
}

// resolveBundleConflict applies the conflict policy to a pending bundle write.
// It returns whether the caller should proceed with the write, after deleting
// the existing referrers the write supersedes. REPLACE deletes every matching
// referrer; SKIPSAME keeps one whose payload is byte-identical to the pending
// write, or that already says the same about this digest (see
// statementCovers), skipping the write, and deletes the rest. Both modes converge on a
// single bundle per predicate type, so accumulation cannot outlive the next
// write even on repositories whose retention never reaps referrer manifests.
func resolveBundleConflict(digest name.Digest, predicateType string, newPayload []byte, conflict string, ropt []remote.Option, opts []ociremote.Option) (bool, error) {
	switch conflict {
	case "", Append:
		return true, nil
	case SkipSame, Replace:
	default:
		return false, fmt.Errorf("unknown conflict mode: %q", conflict)
	}

	matching, err := matchingBundleReferrers(digest, predicateType, opts, ropt)
	if err != nil {
		return false, err
	}

	shouldWrite, deleted, err := supersedeBundleReferrers(digest, newPayload, conflict, matching, ropt)
	if err != nil {
		return false, err
	}

	// On a registry without the native Referrers API, go-containerregistry
	// tracks referrers in a client-maintained sha256-<subject> fallback-tag
	// index. remote.Delete removes the referrer manifest but does NOT prune the
	// descriptor from that index (a documented gap in go-containerregistry's
	// Pusher.Delete). The next writeBundleReferrer would then read the stale
	// index, append the new referrer, and re-PUT an index still referencing the
	// just-deleted manifest, which a registry that validates index members
	// rejects with MANIFEST_UNKNOWN. Prune the deleted descriptors now so the
	// subsequent write commits a consistent index.
	if err := pruneFallbackReferrers(digest, deleted, ropt); err != nil {
		return false, fmt.Errorf("pruning fallback referrers for %q: %w", digest.String(), err)
	}
	return shouldWrite, nil
}

// supersedeBundleReferrers applies the conflict policy to a pending bundle
// write for digest, given the existing bundle referrers of its predicate type
// (see resolveBundleConflict for the policy). It deletes the referrers the
// write supersedes and returns whether to write, together with the digests it
// deleted, for the caller to prune from a fallback-tag index.
func supersedeBundleReferrers(digest name.Digest, newPayload []byte, conflict string, matching []v1.Descriptor, ropt []remote.Option) (bool, []v1.Hash, error) {
	var keep *v1.Hash
	if conflict == SkipSame {
		for _, m := range matching {
			payload, err := referrerDSSEPayload(digest.Repository, m.Digest, ropt)
			if err != nil {
				// A stale referrers-index entry (e.g. Artifact Registry's index
				// lagging a bulk deletion) describes a manifest that no longer
				// exists; it cannot match the new payload.
				if isReferrerNotFound(err) {
					continue
				}
				return false, nil, fmt.Errorf("reading referrer %s: %w", m.Digest, err)
			}
			if bytes.Equal(payload, newPayload) || statementCovers(payload, newPayload, digest) {
				d := m.Digest
				keep = &d
				break
			}
		}
	}

	deleted := make([]v1.Hash, 0, len(matching))
	for _, m := range matching {
		if keep != nil && m.Digest == *keep {
			continue
		}
		ref := digest.Digest(m.Digest.String())
		if err := remote.Delete(ref, ropt...); err != nil && !isReferrerNotFound(err) {
			return false, nil, fmt.Errorf("deleting referrer %s: %w", m.Digest, err)
		}
		// A NOT_FOUND delete means a stale referrers-index entry whose manifest
		// is already gone — the outcome the conflict policy wants. Record it as
		// deleted so pruneFallbackReferrers also drops it from a fallback-tag
		// index.
		deleted = append(deleted, m.Digest)
	}
	return keep == nil, deleted, nil
}

// statementCovers reports whether an existing statement already says about
// digest what a pending one would: the same predicate type and predicate, with
// digest among its subjects under the same name and annotations. The two may
// differ in which other subjects they name.
//
// This is what keeps SKIPSAME stable for multi-subject statements. A digest
// can belong to more than one set of subjects, such as a platform image that
// two indexes share or that a rebuild left unchanged. Each set's statement
// names the digest, and comparing payloads alone would have every write for
// one set replace the other's bundle on that digest, and be replaced in turn.
func statementCovers(existing, pending []byte, digest name.Digest) bool {
	h, err := v1.NewHash(digest.DigestStr())
	if err != nil {
		return false
	}

	type statement struct {
		Type          string           `json:"_type"`
		PredicateType string           `json:"predicateType"`
		Subject       []map[string]any `json:"subject"`
		Predicate     any              `json:"predicate"`
	}
	var have, want statement
	if json.Unmarshal(existing, &have) != nil || json.Unmarshal(pending, &want) != nil {
		return false
	}
	if have.Type != want.Type || have.PredicateType != want.PredicateType || !reflect.DeepEqual(have.Predicate, want.Predicate) {
		return false
	}

	subjectFor := func(subjects []map[string]any) map[string]any {
		for _, subject := range subjects {
			digests, _ := subject["digest"].(map[string]any)
			if digests[h.Algorithm] == h.Hex {
				return subject
			}
		}
		return nil
	}
	haveSubject, wantSubject := subjectFor(have.Subject), subjectFor(want.Subject)
	return haveSubject != nil && wantSubject != nil && reflect.DeepEqual(haveSubject, wantSubject)
}

// pruneFallbackReferrers removes the given descriptors from the sha256-<subject>
// fallback-tag index, if one exists. It is a no-op on registries that implement
// the native Referrers API (they compute referrers dynamically and maintain no
// fallback tag, so the GET below 404s). The fallback tag layout mirrors
// go-containerregistry's unexported fallbackTag: the subject digest with its
// ":" replaced by "-", as a tag on the subject's repository.
func pruneFallbackReferrers(subject name.Digest, deleted []v1.Hash, ropt []remote.Option) error {
	if len(deleted) == 0 {
		return nil
	}

	tag := subject.Context().Tag(strings.Replace(subject.DigestStr(), ":", "-", 1))
	desc, err := remote.Get(tag, ropt...)
	if err != nil {
		if isReferrerNotFound(err) {
			// No fallback index: native Referrers API, or nothing left to prune.
			return nil
		}
		return fmt.Errorf("fetching fallback index %q: %w", tag.String(), err)
	}

	var im v1.IndexManifest
	if err := json.Unmarshal(desc.Manifest, &im); err != nil {
		return fmt.Errorf("parsing fallback index %q: %w", tag.String(), err)
	}

	drop := make(map[v1.Hash]struct{}, len(deleted))
	for _, h := range deleted {
		drop[h] = struct{}{}
	}
	kept := im.Manifests[:0]
	changed := false
	for _, m := range im.Manifests {
		if _, ok := drop[m.Digest]; ok {
			changed = true
			continue
		}
		kept = append(kept, m)
	}
	if !changed {
		return nil
	}
	im.Manifests = kept

	if err := remote.Put(tag, &fallbackIndex{im: im}, ropt...); err != nil {
		return fmt.Errorf("rewriting fallback index %q: %w", tag.String(), err)
	}
	return nil
}

// fallbackIndex serializes a pruned fallback-tag index for a manifest PUT,
// mirroring go-containerregistry's unexported fallbackTaggable.
type fallbackIndex struct {
	im v1.IndexManifest
}

func (f *fallbackIndex) RawManifest() ([]byte, error)            { return json.Marshal(f.im) }
func (f *fallbackIndex) MediaType() (ggcrtypes.MediaType, error) { return ggcrtypes.OCIImageIndex, nil }

func isReferrerNotFound(err error) bool {
	var terr *transport.Error
	return errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound
}

// bundleMediaTypePrefix matches sigstore bundle media types across all
// versions (v0.1 / v0.2 / v0.3 / future v0.4+). Sigstore-go's MediaTypeString
// is version-specific; prefix-matching here mirrors how cosign itself
// filters bundle referrers in pkg/oci/remote/signatures.go.
const bundleMediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// bundleReferrersByPredicateType lists digest's referrers once and returns the
// sigstore bundles among them, grouped by the predicate type each carries.
func bundleReferrersByPredicateType(digest name.Digest, opts []ociremote.Option, ropt []remote.Option) (map[string][]v1.Descriptor, error) {
	idx, err := ociremote.Referrers(digest, "", opts...)
	if err != nil {
		return nil, fmt.Errorf("listing referrers: %w", err)
	}

	byType := map[string][]v1.Descriptor{}
	for _, m := range idx.Manifests {
		predicateType, ok, err := bundleReferrerPredicateType(digest.Repository, m, ropt)
		if err != nil {
			return nil, err
		}
		if ok {
			byType[predicateType] = append(byType[predicateType], m)
		}
	}
	return byType, nil
}

// matchingBundleReferrers returns referrer descriptors for digest that are
// sigstore bundles carrying predicateType.
func matchingBundleReferrers(digest name.Digest, predicateType string, opts []ociremote.Option, ropt []remote.Option) ([]v1.Descriptor, error) {
	byType, err := bundleReferrersByPredicateType(digest, opts, ropt)
	if err != nil {
		return nil, err
	}
	return byType[predicateType], nil
}

// bundleReferrerPredicateType reports whether the referrer described by m is a
// sigstore bundle and, if so, the predicate type it carries. It trusts the
// referrers-index descriptor when the registry populated both artifactType and
// the predicateType annotation, and otherwise consults the referrer manifest,
// which is authoritative on every registry. This keeps REPLACE/SKIPSAME correct
// on registries that omit those fields from the referrers index — notably
// go-containerregistry's tag-schema fallback, whose index descriptors carry an
// artifactType but no annotations.
func bundleReferrerPredicateType(repo name.Repository, m v1.Descriptor, ropt []remote.Option) (string, bool, error) {
	// Fast path: the index descriptor already carries what we need (zot, GAR, …),
	// so no per-referrer manifest fetch is required.
	if strings.HasPrefix(m.ArtifactType, bundleMediaTypePrefix) {
		if pt, ok := m.Annotations[ociremote.BundlePredicateType]; ok {
			return pt, true, nil
		}
	}

	// Slow path: the registry dropped artifactType and/or annotations from the
	// index, or reported the config descriptor's media type as the artifactType
	// (the OCI referrers spec permits this, and cosign bundles use the empty-config
	// media type, so a real bundle can surface here with a non-bundle
	// artifactType). The referrer manifest is authoritative.
	at, ann, err := referrerManifestInfo(repo, m.Digest, ropt)
	if err != nil {
		if isReferrerNotFound(err) {
			// Dangling fallback-index entry for an already-deleted referrer.
			return "", false, nil
		}
		return "", false, err
	}
	if !strings.HasPrefix(at, bundleMediaTypePrefix) {
		return "", false, nil
	}
	pt, ok := ann[ociremote.BundlePredicateType]
	return pt, ok, nil
}

// bundleReferrerMatches reports whether the referrer described by m is a
// sigstore bundle carrying predicateType.
func bundleReferrerMatches(repo name.Repository, m v1.Descriptor, predicateType string, ropt []remote.Option) (bool, error) {
	pt, ok, err := bundleReferrerPredicateType(repo, m, ropt)
	if err != nil {
		return false, err
	}
	return ok && pt == predicateType, nil
}

// referrerManifestInfo fetches a referrer manifest and returns its top-level
// artifactType and annotations.
func referrerManifestInfo(repo name.Repository, descDigest v1.Hash, ropt []remote.Option) (string, map[string]string, error) {
	d, err := remote.Get(repo.Digest(descDigest.String()), ropt...)
	if err != nil {
		return "", nil, err
	}
	var mf struct {
		ArtifactType string            `json:"artifactType"`
		Annotations  map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(d.Manifest, &mf); err != nil {
		return "", nil, fmt.Errorf("parsing referrer manifest %s: %w", descDigest, err)
	}
	return mf.ArtifactType, mf.Annotations, nil
}

// referrerDSSEPayload fetches the given referrer manifest, reads its first
// layer (the protobuf bundle), and returns the bytes of the wrapped DSSE
// envelope payload.
func referrerDSSEPayload(repo name.Repository, descDigest v1.Hash, ropt []remote.Option) ([]byte, error) {
	ref := repo.Digest(descDigest.String())
	img, err := remote.Image(ref, ropt...)
	if err != nil {
		return nil, fmt.Errorf("fetching referrer image: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting layers: %w", err)
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("referrer has no layers")
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("opening layer: %w", err)
	}
	defer rc.Close()

	bundleBytes, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading bundle bytes: %w", err)
	}

	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}
	env := bundle.GetDsseEnvelope()
	if env == nil {
		return nil, fmt.Errorf("bundle has no DSSE envelope")
	}
	return env.Payload, nil
}
