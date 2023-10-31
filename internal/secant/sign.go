package secant

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/chainguard-dev/terraform-provider-cosign/internal/secant/rekor"
	"github.com/chainguard-dev/terraform-provider-cosign/internal/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	"github.com/sigstore/rekor/pkg/generated/client"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

// Sign is roughly equivalent to cosign sign.
func Sign(ctx context.Context, conflict string, annotations map[string]interface{}, sv types.CosignerVerifier, rekorClient *client.Rekor, imgs []string, ropt []remote.Option) error {
	cs := rekor.NewCosigner(sv, rekorClient)

	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}
	signOpts := []mutate.SignOption{}
	switch conflict {
	case "APPEND":
		// Don't add any options. Without replace op or dupe detector, we will append.
	case "REPLACE":
		signOpts = append(signOpts, mutate.WithReplaceOp(replaceSignatures{}))
	case "SKIPSAME":
		signOpts = append(signOpts, mutate.WithDupeDetector(skipSameSignatures{}))
	default:
		// This should not happen because schema validation would catch it.
		return fmt.Errorf("unhandled conflict type: %q", conflict)
	}

	for _, inputImg := range imgs {
		ref, err := name.ParseReference(inputImg)
		if err != nil {
			return err
		}

		se, err := ociremote.SignedEntity(ref, opts...)
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
			if err := signDigest(ctx, digest, annotations, signOpts, cs, se, opts); err != nil {
				return fmt.Errorf("signing digest: %w", err)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("recursively signing: %w", err)
		}
	}

	return nil
}

func signDigest(ctx context.Context, digest name.Digest, annotations map[string]interface{}, signOpts []mutate.SignOption, cs types.Cosigner, se oci.SignedEntity, opts []ociremote.Option) error {
	payload, err := (&sigPayload.Cosign{
		Image:       digest,
		Annotations: annotations,
	}).MarshalJSON()
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}

	ociSig, err := cs.Cosign(ctx, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(se, ociSig, signOpts...)
	if err != nil {
		return err
	}

	// Publish the signatures associated with this entity
	return ociremote.WriteSignatures(digest.Repository, newSE, opts...)
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
