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

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/models/rekord"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/tlog"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// AttachHashedRekord uploads information about the signature to Rekor and attaches a Rekor bundle to the signature.
func AttachHashedRekord(ctx context.Context, rekorClient *client.Rekor, sig oci.Signature) (oci.Signature, error) {
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

	entry, err := tlog.Upload(ctx, rekorClient, pe)
	if err != nil {
		return nil, err
	}

	bundle := cbundle.EntryToBundle(entry)
	return mutate.Signature(sig, mutate.WithBundle(bundle))
}
