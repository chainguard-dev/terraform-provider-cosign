package intoto

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-openapi/runtime"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/intoto"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
)

// TODO: Avoid depending on rekor/pkg/types as much as possible
func Entry(ctx context.Context, signature, pubKey []byte) (models.ProposedEntry, error) {
	return rekortypes.NewProposedEntry(ctx, intoto.KIND, intoto_v001.APIVERSION, rekortypes.ArtifactProperties{
		ArtifactBytes:  signature,
		PublicKeyBytes: [][]byte{pubKey},
	})
}

func PayloadHash(bundle *bundle.RekorBundle) (*v1.Hash, error) {
	body, ok := bundle.Payload.Body.(string)
	if !ok {
		return nil, fmt.Errorf("bundle payload body is %T, expected string", bundle.Payload.Body)
	}
	dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(body))
	pe, err := models.UnmarshalProposedEntry(dec, runtime.JSONConsumer())
	if err != nil {
		return nil, fmt.Errorf("UnmarshaslProposedEntry: %w", err)
	}

	impl, err := rekortypes.UnmarshalEntry(pe)
	if err != nil {
		return nil, fmt.Errorf("UnmarshalEntry: %w", err)
	}

	entry, ok := impl.(*intoto_v001.V001Entry)
	if !ok {
		return nil, fmt.Errorf("entry is %T, expected intoto 0.0.1", impl)
	}

	return &v1.Hash{
		Algorithm: *entry.IntotoObj.Content.PayloadHash.Algorithm,
		Hex:       *entry.IntotoObj.Content.PayloadHash.Value,
	}, nil
}
