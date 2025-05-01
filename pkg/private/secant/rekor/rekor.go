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
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/models/rekord"
	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/tlog"
	"github.com/go-openapi/runtime"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekortypes "github.com/sigstore/rekor/pkg/types"
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

// PayloadHash extracts the payload hash from the provided rekor bundle.
func PayloadHash(bundle *cbundle.RekorBundle) (v1.Hash, error) {
	body, ok := bundle.Payload.Body.(string)
	if !ok {
		return v1.Hash{}, fmt.Errorf("bundle payload body is %T, expected string", bundle.Payload.Body)
	}
	dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(body))
	pe, err := models.UnmarshalProposedEntry(dec, runtime.JSONConsumer())
	if err != nil {
		return v1.Hash{}, fmt.Errorf("UnmarshaslProposedEntry: %w", err)
	}

	impl, err := rekortypes.UnmarshalEntry(pe)
	if err != nil {
		return v1.Hash{}, fmt.Errorf("UnmarshalEntry: %w", err)
	}
	hash, err := impl.ArtifactHash()
	if err != nil {
		return v1.Hash{}, fmt.Errorf("reading artifact hash: %w", err)
	}
	return v1.NewHash(hash)
}
