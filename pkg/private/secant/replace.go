package secant

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
)

const (
	// Replace replaces signatures on the image
	Replace = "REPLACE"
	// SkipSame skips writing identical signatures but otherwise replaces signatures on the image.
	SkipSame = "SKIPSAME"
	// Append appends signatures on the image.
	Append = "APPEND"
)

func getPredicateType(s oci.Signature) (string, error) {
	anns, err := s.Annotations()
	if err != nil {
		return "", fmt.Errorf("could not get annotations: %w", err)
	}

	// Fast path: we have this in the top-level annotations.
	if pt, ok := anns["predicateType"]; ok {
		return pt, nil
	}

	// Otherwise we need to fetch and parse the payload.
	var signaturePayload map[string]interface{}
	p, err := s.Payload()
	if err != nil {
		return "", fmt.Errorf("could not get payload: %w", err)
	}
	err = json.Unmarshal(p, &signaturePayload)
	if err != nil {
		return "", fmt.Errorf("unmarshal payload data: %w", err)
	}

	val, ok := signaturePayload["payload"]
	if !ok {
		return "", fmt.Errorf("could not find 'payload' in payload data")
	}
	decodedPayload, err := base64.StdEncoding.DecodeString(val.(string))
	if err != nil {
		return "", fmt.Errorf("could not decode 'payload': %w", err)
	}

	var payloadData map[string]interface{}
	if err := json.Unmarshal(decodedPayload, &payloadData); err != nil {
		return "", fmt.Errorf("unmarshal payloadData: %w", err)
	}
	val, ok = payloadData["predicateType"]
	if !ok {
		return "", fmt.Errorf("could not find 'predicateType' in payload data")
	}

	pt, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("expected predicateType to be string, got type %T: %v", val, val)
	}
	return pt, nil
}

type replaceOCISignatures struct {
	oci.Signatures
	sigs []oci.Signature
}

func (r *replaceOCISignatures) Get() ([]oci.Signature, error) {
	return r.sigs, nil
}

type replaceSignedEntityAttestations struct {
	oci.SignedEntity
	atts []oci.Signature
}

func (r *replaceSignedEntityAttestations) Attestations() (oci.Signatures, error) {
	atts, err := r.SignedEntity.Attestations()
	if err != nil {
		return nil, err
	}
	replaced, err := mutate.ReplaceSignatures(&replaceOCISignatures{Signatures: atts, sigs: r.atts})
	if err != nil {
		return nil, err
	}
	return replaced, err
}
