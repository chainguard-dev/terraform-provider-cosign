// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rekor

import (
	"context"
	"crypto/sha256"
	"io"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/models/rekord"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/tlog"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// signerWrapper calls a wrapped, inner signer then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
type signerWrapper struct {
	inner types.Cosigner

	client *client.Rekor
}

var _ types.Cosigner = (*signerWrapper)(nil)

// Cosign implements Cosigner.
func (rs *signerWrapper) Cosign(ctx context.Context, payload io.Reader) (oci.Signature, error) {
	sig, err := rs.inner.Cosign(ctx, payload)
	if err != nil {
		return nil, err
	}

	payloadBytes, err := sig.Payload()
	if err != nil {
		return nil, err
	}
	sigBytes, err := sig.Signature()
	if err != nil {
		return nil, err
	}

	// Upload the cert or the public key, depending on what we have
	cert, err := sig.Cert()
	if err != nil {
		return nil, err
	}

	rekorBytes, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}

	checkSum := sha256.New()
	if _, err := checkSum.Write(payloadBytes); err != nil {
		return nil, err
	}

	pe := rekord.Entry(checkSum, sigBytes, rekorBytes)

	entry, err := tlog.Upload(ctx, rs.client, pe)
	if err != nil {
		return nil, err
	}

	bundle, err := cbundle.EntryToBundle(entry), nil
	if err != nil {
		return nil, err
	}

	newSig, err := mutate.Signature(sig, mutate.WithBundle(bundle))
	if err != nil {
		return nil, err
	}

	return newSig, nil
}

// NewCosigner returns a Cosigner which uploads the signature to Rekor
func NewCosigner(inner types.Cosigner, client *client.Rekor) types.Cosigner {
	return &signerWrapper{
		inner:  inner,
		client: client,
	}
}
