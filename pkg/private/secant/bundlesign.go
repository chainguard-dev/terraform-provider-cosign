package secant

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/fulcio"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/walk"
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

// BundleSignerOption customizes a BundleSigner at construction.
type BundleSignerOption func(*bundleSignerConfig)

type bundleSignerConfig struct {
	signingConfig   *root.SigningConfig
	trustedMaterial root.TrustedMaterial
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
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	return &BundleSigner{
		oidc:            oidc,
		signingConfig:   cfg.signingConfig,
		trustedMaterial: cfg.trustedMaterial,
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

	bundleBytes, err := cbundle.SignData(ctx, content, bs.keypair, idToken, nil, nil, bs.signingConfig, bs.trustedMaterial, cbundle.SignOptions{})
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
	// Every SignContent ends in one transparency-log upload, and the
	// Rekor v2 write client does not retry a 429 — gate it through the
	// same limiter as the legacy paths. Wait before taking the mutex so
	// a throttled caller doesn't block concurrent cached-cert signs.
	if RekorRateLimiter != nil {
		if err := RekorRateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("waiting for rekor rate limiter: %w", err)
		}
	}

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
	bundle, err := cbundle.SignData(ctx, content, bs.keypair, "", certPEM, nil, bs.signingConfig, bs.trustedMaterial, cbundle.SignOptions{})
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}
	return bundle, nil
}

// contentSigner is the part of BundleSigner that SignBundle consumes — the
// seam that lets tests drive the walk and write fan-out without Fulcio.
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
			d, err := se.Digest()
			if err != nil {
				return fmt.Errorf("computing digest: %w", err)
			}
			return signBundleDigest(ctx, conflict, annotations, signer, ref.Context().Digest(d.String()), ropt, opts)
		}); err != nil {
			return fmt.Errorf("recursively signing: %w", err)
		}
	}

	return nil
}

// signBundleDigest signs exactly one digest with a sign-predicate bundle,
// applying the conflict policy against its existing referrers.
func signBundleDigest(ctx context.Context, conflict string, annotations map[string]any, signer contentSigner, digest name.Digest, ropt []remote.Option, opts []ociremote.Option) error {
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

	shouldWrite, err := resolveBundleConflict(digest, ctypes.CosignSignPredicateType, payload, conflict, ropt, opts)
	if err != nil {
		return fmt.Errorf("resolving conflict for %q: %w", digest.String(), err)
	}
	if !shouldWrite {
		return nil
	}

	content := &sign.DSSEData{
		Data:        payload,
		PayloadType: ctypes.IntotoPayloadType,
	}

	bundleBytes, err := signer.SignContent(ctx, content)
	if err != nil {
		return fmt.Errorf("signing bundle for %q: %w", digest.String(), err)
	}

	if err := writeBundleReferrer(digest, bundleBytes, ctypes.CosignSignPredicateType, nil, ropt); err != nil {
		return fmt.Errorf("writing sign bundle for %q: %w", digest.String(), err)
	}

	return nil
}

// AttestBundle creates attestations using the cosign v3 bundle format
// and writes them as OCI referrers. See SignBundle for conflict semantics.
// Statements may carry a verbatim subject descriptor (Statement.SubjectDescriptor)
// for subjects that are absent from the target repository.
func AttestBundle(ctx context.Context, conflict string, statements []*types.Statement, signer *BundleSigner, ropt []remote.Option) error {
	if len(statements) == 0 {
		return nil
	}

	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	for _, stmt := range statements {
		predicateType, err := parsePredicateType(stmt.Type)
		if err != nil {
			return err
		}

		shouldWrite, err := resolveBundleConflict(stmt.Digest, predicateType, stmt.Payload, conflict, ropt, ociOpts)
		if err != nil {
			return fmt.Errorf("resolving conflict for %q: %w", stmt.Digest.String(), err)
		}
		if !shouldWrite {
			continue
		}

		content := &sign.DSSEData{
			Data:        stmt.Payload,
			PayloadType: ctypes.IntotoPayloadType,
		}

		bundleBytes, err := signer.SignContent(ctx, content)
		if err != nil {
			return fmt.Errorf("signing attestation bundle for %q: %w", stmt.Digest.String(), err)
		}

		if err := writeBundleReferrer(stmt.Digest, bundleBytes, predicateType, stmt.SubjectDescriptor, ropt); err != nil {
			return fmt.Errorf("writing attestation bundle for %q: %w", stmt.Digest.String(), err)
		}
	}

	return nil
}

// resolveBundleConflict applies the conflict policy to a pending bundle write.
// It returns whether the caller should proceed with the write, after deleting
// the existing referrers the write supersedes. REPLACE deletes every matching
// referrer; SKIPSAME keeps one whose payload is byte-identical to the pending
// write (skipping the write) and deletes the rest. Both modes converge on a
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
				return false, fmt.Errorf("reading referrer %s: %w", m.Digest, err)
			}
			if bytes.Equal(payload, newPayload) {
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
			return false, fmt.Errorf("deleting referrer %s: %w", m.Digest, err)
		}
		// A NOT_FOUND delete means a stale referrers-index entry whose manifest
		// is already gone — the outcome the conflict policy wants. Record it as
		// deleted so pruneFallbackReferrers also drops it from a fallback-tag
		// index.
		deleted = append(deleted, m.Digest)
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
	return keep == nil, nil
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

// matchingBundleReferrers returns referrer descriptors for digest that are
// sigstore bundles carrying predicateType. It trusts the referrers-index
// descriptor when the registry populated both artifactType and the
// predicateType annotation, and otherwise consults the referrer manifest, which
// is authoritative on every registry. This keeps REPLACE/SKIPSAME correct on
// registries that omit those fields from the referrers index — notably
// go-containerregistry's tag-schema fallback, whose index descriptors carry an
// artifactType but no annotations.
func matchingBundleReferrers(digest name.Digest, predicateType string, opts []ociremote.Option, ropt []remote.Option) ([]v1.Descriptor, error) {
	idx, err := ociremote.Referrers(digest, "", opts...)
	if err != nil {
		return nil, fmt.Errorf("listing referrers: %w", err)
	}

	var matching []v1.Descriptor
	for _, m := range idx.Manifests {
		ok, err := bundleReferrerMatches(digest.Repository, m, predicateType, ropt)
		if err != nil {
			return nil, err
		}
		if ok {
			matching = append(matching, m)
		}
	}
	return matching, nil
}

// bundleReferrerMatches reports whether the referrer described by m is a
// sigstore bundle carrying predicateType.
func bundleReferrerMatches(repo name.Repository, m v1.Descriptor, predicateType string, ropt []remote.Option) (bool, error) {
	// Fast path: the index descriptor already carries what we need (zot, GAR, …),
	// so no per-referrer manifest fetch is required.
	if strings.HasPrefix(m.ArtifactType, bundleMediaTypePrefix) {
		if pt, ok := m.Annotations[ociremote.BundlePredicateType]; ok {
			return pt == predicateType, nil
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
			return false, nil
		}
		return false, err
	}
	return strings.HasPrefix(at, bundleMediaTypePrefix) &&
		ann[ociremote.BundlePredicateType] == predicateType, nil
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
