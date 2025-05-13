package secant

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/rekor"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	"github.com/sigstore/rekor/pkg/generated/client"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
	"golang.org/x/time/rate"
)

// SignEntity is roughly equivalent to cosign sign.
// It operates on the provided oci.SignedEntity without interacting with the registry.
func SignEntity(ctx context.Context, se oci.SignedEntity, subject name.Digest, conflict string, annotations map[string]interface{}, cs types.Cosigner, rekorClient *client.Rekor, opts ...SignOption) (oci.SignedEntity, error) {
	o, err := makeSignOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("initializing sign options: %w", err)
	}
	// Get the digest for this entity in our walk.
	d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
	if err != nil {
		return nil, fmt.Errorf("computing digest: %w", err)
	}
	digest := subject.Context().Digest(d.String())
	payload, err := (&sigPayload.Cosign{
		Image:       digest,
		Annotations: annotations,
	}).MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}

	ociSig, err := cs.Cosign(ctx, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	currentSigs, err := se.Signatures()
	if err != nil {
		return nil, fmt.Errorf("getting current signatures: %w", err)
	}
	signOpts := []mutate.SignOption{}
	switch conflict {
	case Append:
		// Don't add any options. Without replace op or dupe detector, we will append.
	case Replace:
		signOpts = append(signOpts, mutate.WithReplaceOp(replaceSignatures{}))
	case SkipSame:
		// We intentionally avoid mutate.WithDupeDetector so that we can skip uploading
		// anything to rekor in case of a duplicate.
		match, err := skipSameSignatures{}.Find(currentSigs, ociSig)
		if err != nil {
			return nil, fmt.Errorf("finding matching signatures: %w", err)
		}
		if match != nil {
			return se, nil
		}
	default:
		// This should not happen because schema validation would catch it.
		return nil, fmt.Errorf("unhandled conflict type: %q", conflict)
	}

	if o.rekorLimiter != nil {
		if err := o.rekorLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("waiting for rekor rate limiter: %w", err)
		}
	}
	ociSig, err = rekor.AttachHashedRekord(ctx, rekorClient, ociSig)
	if err != nil {
		return nil, fmt.Errorf("attaching rekor bundle: %w", err)
	}

	// Attach the signature to the entity.
	return mutate.AttachSignatureToEntity(se, ociSig, signOpts...)
}

// Sign is roughly equivalent to cosign sign.
func Sign(ctx context.Context, conflict string, annotations map[string]interface{}, sv types.CosignerVerifier, rekorClient *client.Rekor, imgs []name.Digest, ropt []remote.Option, opts ...SignOption) error {
	rOpts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	for _, ref := range imgs {
		se, err := ociremote.SignedEntity(ref, rOpts...)
		if err != nil {
			return fmt.Errorf("accessing entity: %w", err)
		}

		if err := walk.SignedEntity(ctx, se, func(ctx context.Context, se oci.SignedEntity) error {
			// Get the digest for this entity in our walk.
			d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
			if err != nil {
				return fmt.Errorf("computing digest: %w", err)
			}
			digest := ref.Context().Digest(d.String())
			newSE, err := SignEntity(ctx, se, digest, conflict, annotations, sv, rekorClient, opts...)
			if err != nil {
				return fmt.Errorf("signing digest: %w", err)
			}
			// Publish the signatures associated with this entity
			return ociremote.WriteSignatures(digest.Repository, newSE, rOpts...)
		}); err != nil {
			return fmt.Errorf("recursively signing: %w", err)
		}
	}

	return nil
}

type replaceSignatures struct{}

func (r replaceSignatures) Replace(signatures oci.Signatures, o oci.Signature) (oci.Signatures, error) {
	sigs, err := signatures.Get()
	if err != nil {
		return nil, err
	}

	ros := &replaceOCISignatures{Signatures: signatures}

	sigsCopy := make([]oci.Signature, 0, len(sigs))
	sigsCopy = append(sigsCopy, o)

	if len(sigs) == 0 {
		ros.sigs = append(ros.sigs, sigsCopy...)
		return ros, nil
	}

	digest, err := o.Digest()
	if err != nil {
		return nil, err
	}

	for _, s := range sigs {
		existingDigest, err := s.Digest()
		if err != nil {
			return nil, err
		}

		if digest == existingDigest {
			fmt.Fprintln(os.Stderr, "Replacing signature with digest:", digest)
			continue
		}

		fmt.Fprintln(os.Stderr, "Not replacing signature with digest:", digest)
		sigsCopy = append(sigsCopy, s)
	}

	ros.sigs = append(ros.sigs, sigsCopy...)

	return ros, nil
}

type skipSameSignatures struct{}

func (r skipSameSignatures) Find(signatures oci.Signatures, o oci.Signature) (oci.Signature, error) {
	sigs, err := signatures.Get()
	if err != nil {
		return nil, err
	}

	digest, err := o.Digest()
	if err != nil {
		return nil, err
	}

	for _, s := range sigs {
		existingDigest, err := s.Digest()
		if err != nil {
			return nil, err
		}

		if digest == existingDigest {
			return s, nil
		}
	}

	return nil, nil
}

type signOptions struct {
	rekorLimiter *rate.Limiter
}

type SignOption (func(*signOptions) error)

func makeSignOptions(opts []SignOption) (*signOptions, error) {
	o := &signOptions{
		rekorLimiter: defaultRekorLimiter,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// WithSignRekorLimiter rate limits calls to Rekor
func WithSignRekorLimiter(limiter *rate.Limiter) AttestOption {
	return func(o *attestOptions) error {
		o.rekorLimiter = limiter
		return nil
	}
}
