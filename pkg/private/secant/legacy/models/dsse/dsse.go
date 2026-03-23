package dsse

import (
	"context"

	"github.com/sigstore/rekor/pkg/generated/models"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/dsse"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
)

// Entry creates a dsse ProposedEntry.
func Entry(ctx context.Context, signature, pubKey []byte) (models.ProposedEntry, error) {
	return rekortypes.NewProposedEntry(ctx, dsse.KIND, dsse_v001.APIVERSION, rekortypes.ArtifactProperties{
		ArtifactBytes:  signature,
		PublicKeyBytes: [][]byte{pubKey},
	})
}
