package intoto

import (
	"context"

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
