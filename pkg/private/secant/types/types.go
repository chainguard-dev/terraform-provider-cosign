package types

import (
	"context"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/sigstore/pkg/signature"
)

type Cosigner interface {
	Cosign(context.Context, io.Reader) (oci.Signature, error)
}

type CosignerSigner interface {
	signature.Signer
	Cosigner
}

type CosignerSignerVerifier interface {
	Cosigner
	signature.Signer
	signature.Verifier
}

type CosignerVerifier interface {
	Cosigner
	signature.Verifier
}

type Statement struct {
	Digest  name.Digest
	Type    string
	Payload []byte
	// SubjectDescriptor, when non-nil, is used verbatim as the subject
	// descriptor of the referrer manifest written by AttestBundle — the subject
	// manifest need not exist in the target repository, but the descriptor's
	// digest must match Digest. When nil, the descriptor is resolved via HEAD
	// against Digest and any failure (including 404) is an error, matching
	// cosign's WriteReferrer. Ignored by the legacy tag-based Attest path.
	SubjectDescriptor *v1.Descriptor
}
