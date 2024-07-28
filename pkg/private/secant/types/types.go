package types

import (
	"context"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/oci"
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
}
