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
)

// SignConflictOp merges a set of proposed intoto Statements into an existing set of attestation signatures.
type SignConflictOp interface {
	MergeSignatures(base []oci.Signature, payload []byte) (newBase []oci.Signature, shouldSign bool, err error)
}

// Sign is roughly equivalent to cosign sign.
func Sign(ctx context.Context, conflictOp SignConflictOp, annotations map[string]interface{}, sv types.CosignerVerifier, rekorClient *client.Rekor, imgs []name.Digest, ropt []remote.Option) error {
	cs := rekor.NewCosigner(sv, rekorClient)

	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}
	signOpts := []mutate.SignOption{}

	for _, ref := range imgs {
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
			payload, err := (&sigPayload.Cosign{
				Image:       digest,
				Annotations: annotations,
			}).MarshalJSON()
			if err != nil {
				return fmt.Errorf("payload: %w", err)
			}
			signatures, err := se.Signatures()
			if err != nil {
				return fmt.Errorf("getting signatures: %w", err)
			}
			sigs, err := signatures.Get()
			if err != nil {
				return fmt.Errorf("reading signatures: %w", err)
			}
			newSigs, shouldSign, err := conflictOp.MergeSignatures(sigs, payload)
			if err != nil {
				return fmt.Errorf("merging signatures: %w", err)
			}
			if !shouldSign {
				fmt.Fprintln(os.Stderr, "Skipping signing digest:", digest)
				return nil
			}
			se = &replaceSignedEntitySignatures{SignedEntity: se, sigs: newSigs}

			if err := signDigest(ctx, digest, payload, signOpts, cs, se, opts); err != nil {
				return fmt.Errorf("signing digest: %w", err)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("recursively signing: %w", err)
		}
	}

	return nil
}

func signDigest(ctx context.Context, digest name.Digest, payload []byte, signOpts []mutate.SignOption, cs types.Cosigner, se oci.SignedEntity, opts []ociremote.Option) error {
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

func (r *ReplaceOp) MergeSignatures(sigs []oci.Signature, payload []byte) ([]oci.Signature, bool, error) {
	var result []oci.Signature
	shouldSign := true

	digest, _, err := v1.SHA256(bytes.NewReader(payload))
	if err != nil {
		return nil, false, fmt.Errorf("calculating digest: %w", err)
	}

	for _, s := range sigs {
		existingDigest, err := s.Digest()
		if err != nil {
			return nil, false, err
		}

		if digest == existingDigest {
			if r.SkipSame {
				fmt.Fprintln(os.Stderr, "Skipping signing for signature as digest:", digest)
				shouldSign = false
				result = append(result, s)
			} else {
				fmt.Fprintln(os.Stderr, "Replacing signature with digest:", digest)
			}
			continue
		}

		fmt.Fprintln(os.Stderr, "Not replacing signature with digest:", digest)
		result = append(result, s)
	}

	return result, shouldSign, nil
}

func (a *AppendOp) MergeSignatures(sigs []oci.Signature, payload []byte) ([]oci.Signature, bool, error) {
	return sigs, true, nil
}
