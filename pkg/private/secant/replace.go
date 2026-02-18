package secant

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigstore/cosign/v2/pkg/oci"
)

const (
	// Replace replaces signatures on the image.
	Replace = "REPLACE"
	// SkipSame skips writing identical signatures but otherwise replaces signatures on the image.
	SkipSame = "SKIPSAME"
	// Append appends signatures on the image.
	Append = "APPEND"
)

func replacePredicate(predicateType string) *ro {
	return &ro{predicateType: predicateType}
}

type ro struct {
	predicateType string
}

func (r *ro) Replace(signatures oci.Signatures, o oci.Signature) (oci.Signatures, error) {
	sigs, err := signatures.Get()
	if err != nil {
		return nil, err
	}

	ros := &replaceOCISignatures{Signatures: signatures}

	sigsCopy := make([]oci.Signature, 0, len(sigs))
	sigsCopy = append(sigsCopy, o)

	if len(sigs) == 0 {
		ros.sigs = append(ros.sigs, sigsCopy...)
		return ros, nil
	}

	for _, s := range sigs {
		pt, err := getPredicateType(s)
		if err != nil {
			return nil, err
		}

		if r.predicateType == pt {
			fmt.Fprintln(os.Stderr, "Replacing attestation predicate:", r.predicateType)
			continue
		}

		fmt.Fprintln(os.Stderr, "Not replacing attestation predicate:", pt)
		sigsCopy = append(sigsCopy, s)
	}

	ros.sigs = append(ros.sigs, sigsCopy...)

	return ros, nil
}

func getPredicateType(s sigsubset) (string, error) {
	anns, err := s.Annotations()
	if err != nil {
		return "", fmt.Errorf("could not get annotations: %w", err)
	}

	// Fast path: we have this in the top-level annotations.
	if pt, ok := anns["predicateType"]; ok {
		return pt, nil
	}

	// Otherwise we need to fetch and parse the payload.
	var signaturePayload map[string]any
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
	valStr, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("expected payload to be a string, got %T", val)
	}
	decodedPayload, err := base64.StdEncoding.DecodeString(valStr)
	if err != nil {
		return "", fmt.Errorf("could not decode 'payload': %w", err)
	}

	var payloadData map[string]any
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
