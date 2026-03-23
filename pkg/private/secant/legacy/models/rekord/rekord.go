package rekord

import (
	"encoding/hex"
	"hash"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	"github.com/sigstore/rekor/pkg/generated/models"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

func Entry(sha256CheckSum hash.Hash, signature, pubKey []byte) models.ProposedEntry {
	// TODO: Signatures created on a digest using a hash algorithm other than SHA256 will fail
	// upload right now. Plumb information on the hash algorithm used when signing from the
	// SignerVerifier to use for the HashedRekordObj.Data.Hash.Algorithm.
	re := hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: conv.Pointer(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
					Value:     conv.Pointer(hex.EncodeToString(sha256CheckSum.Sum(nil))),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(pubKey),
				},
			},
		},
	}
	pe := models.Hashedrekord{
		APIVersion: conv.Pointer(re.APIVersion()),
		Spec:       re.HashedRekordObj,
	}

	return &pe
}
