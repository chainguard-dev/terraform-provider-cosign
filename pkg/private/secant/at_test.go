package secant

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
)

func TestNewStatements(t *testing.T) {
	digest, err := name.NewDigest("example.com/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	sbody := []byte(`{"key": "I'm an SBOM"}`)
	sbom, err := NewStatement(digest, bytes.NewReader(sbody), "https://example.com/sbom")
	if err != nil {
		t.Fatal(err)
	}

	sbody2 := []byte(`{"key": "I'm also an SBOM"}`)
	sbom2, err := NewStatement(digest, bytes.NewReader(sbody2), "https://example.com/sbom")
	if err != nil {
		t.Fatal(err)
	}

	provBody := []byte(`{"key": "I'm a provenance"}`)
	prov, err := NewStatement(digest, bytes.NewReader(provBody), "https://example.com/prov")
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range []struct {
		statements []*types.Statement
		sigments   []*sigment
		conflict   string
		want       int
		err        bool
	}{{
		statements: []*types.Statement{sbom, sbom2, prov},
		sigments:   []*sigment{},
		conflict:   "APPEND",
		want:       3,
	}, {
		statements: []*types.Statement{sbom, sbom2, prov},
		sigments:   sigments(sbom, sbom2, prov),
		conflict:   "APPEND",
		want:       3,
	}, {
		statements: []*types.Statement{sbom, sbom2, prov},
		sigments:   []*sigment{},
		conflict:   "REPLACE",
		err:        true,
	}, {
		statements: []*types.Statement{sbom2, prov},
		sigments:   sigments(sbom, sbom2, prov),
		conflict:   "REPLACE",
		want:       2,
	}, {
		statements: []*types.Statement{sbom, sbom2, prov},
		sigments:   []*sigment{},
		conflict:   "SKIPSAME",
		err:        true,
	}, {
		statements: []*types.Statement{sbom2, prov},
		sigments:   sigments(sbom, sbom2, prov),
		conflict:   "SKIPSAME",
		want:       1,
	}, {
		statements: []*types.Statement{sbom2, prov},
		sigments:   sigments(sbom2, prov),
		conflict:   "SKIPSAME",
		want:       0,
	}} {
		t.Run(fmt.Sprintf("newStatements[%d]", i), func(t *testing.T) {
			statements, err := newStatements(tc.statements, tc.sigments, tc.conflict)
			if err != nil {
				if !tc.err {
					t.Error(err)
				}
				return
			}

			if got, want := len(statements), tc.want; got != want {
				t.Errorf("got %d new statments, want %d", got, want)
			}
		})
	}
}

func sigments(stmts ...*types.Statement) []*sigment {
	result := []*sigment{}
	for _, s := range stmts {
		result = append(result, &sigment{s})
	}

	return result
}

// Turns a statement into an oci.Signature.
type sigment struct {
	statement *types.Statement
}

func (s *sigment) Annotations() (map[string]string, error) {
	pt, err := parsePredicateType(s.statement.Type)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"predicateType": pt,
	}, nil
}

func (s *sigment) Payload() ([]byte, error) {
	return nil, errors.New("this should not get called because of Annotations")
}

func (s *sigment) Bundle() (*bundle.RekorBundle, error) {
	return &bundle.RekorBundle{
		SignedEntryTimestamp: []byte("unused"),
		Payload: bundle.RekorPayload{
			Body:           s.body(),
			IntegratedTime: 0,
			LogIndex:       0,
			LogID:          "unused",
		},
	}, nil
}

func (s *sigment) body() string {
	return base64.StdEncoding.EncodeToString([]byte(s.rawBody()))
}

const bodyTmpl = `{
  "apiVersion": "0.0.1",
	"kind": "intoto",
	"spec": {
	  "content": {
	  	"hash": {
	    	"algorithm": "sha256",
	    	"value": "%s"
	  	},
	  	"payloadHash": {
	    	"algorithm": "sha256",
	    	"value": "%s"
	  	}
	  },
	  "publicKey": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUc4RENDQm5lZ0F3SUJBZ0lVZlZFdngrSkNENjdYUWg2TTd5QzJrZTJSMXE4d0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpNeE1ERXpNakV6TURFeldoY05Nak14TURFek1qRTBNREV6V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVPM2tIQkZIV3VudDNCd1JQdHNyTXZCVTd0eGNnRG96em9TVDIKM2d5Qlp5VjNlSG9yZ0dZb1VBZnJnTWFyRTdmVFdEWHAwdzN0OW1ZOE0rK0JoWmUvQnFPQ0JaWXdnZ1dTTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVU3YmpJCmJsbEdIeUlEWE10WHNieWZYN0NMWkUwd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d2FBWURWUjBSQVFIL0JGNHdYSVphYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJOb1lXbHVaM1ZoY21RdAphVzFoWjJWekwybHRZV2RsY3k4dVoybDBhSFZpTDNkdmNtdG1iRzkzY3k5eVpXeGxZWE5sTG5saGJXeEFjbVZtCmN5OW9aV0ZrY3k5dFlXbHVNRGtHQ2lzR0FRUUJnNzh3QVFFRUsyaDBkSEJ6T2k4dmRHOXJaVzR1WVdOMGFXOXUKY3k1bmFYUm9kV0oxYzJWeVkyOXVkR1Z1ZEM1amIyMHdFZ1lLS3dZQkJBR0R2ekFCQWdRRWNIVnphREEyQmdvcgpCZ0VFQVlPL01BRURCQ2d3TUdVeU1XTmpORGc0TkdJeVptRTNNV0k1TW1VNE1EVXhPVEZqWVdSbE56QTRNV0UzCk1qQXhNQ3dHQ2lzR0FRUUJnNzh3QVFRRUhpNW5hWFJvZFdJdmQyOXlhMlpzYjNkekwzSmxiR1ZoYzJVdWVXRnQKYkRBbUJnb3JCZ0VFQVlPL01BRUZCQmhqYUdGcGJtZDFZWEprTFdsdFlXZGxjeTlwYldGblpYTXdIUVlLS3dZQgpCQUdEdnpBQkJnUVBjbVZtY3k5b1pXRmtjeTl0WVdsdU1Ec0dDaXNHQVFRQmc3OHdBUWdFTFF3cmFIUjBjSE02Ckx5OTBiMnRsYmk1aFkzUnBiMjV6TG1kcGRHaDFZblZ6WlhKamIyNTBaVzUwTG1OdmJUQnFCZ29yQmdFRUFZTy8KTUFFSkJGd01XbWgwZEhCek9pOHZaMmwwYUhWaUxtTnZiUzlqYUdGcGJtZDFZWEprTFdsdFlXZGxjeTlwYldGbgpaWE12TG1kcGRHaDFZaTkzYjNKclpteHZkM012Y21Wc1pXRnpaUzU1WVcxc1FISmxabk12YUdWaFpITXZiV0ZwCmJqQTRCZ29yQmdFRUFZTy9NQUVLQkNvTUtEQXdaVEl4WTJNME9EZzBZakptWVRjeFlqa3laVGd3TlRFNU1XTmgKWkdVM01EZ3hZVGN5TURFd0hRWUtLd1lCQkFHRHZ6QUJDd1FQREExbmFYUm9kV0l0YUc5emRHVmtNRHNHQ2lzRwpBUVFCZzc4d0FRd0VMUXdyYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJOb1lXbHVaM1ZoY21RdGFXMWhaMlZ6CkwybHRZV2RsY3pBNEJnb3JCZ0VFQVlPL01BRU5CQ29NS0RBd1pUSXhZMk0wT0RnMFlqSm1ZVGN4WWpreVpUZ3cKTlRFNU1XTmhaR1UzTURneFlUY3lNREV3SHdZS0t3WUJCQUdEdnpBQkRnUVJEQTl5WldaekwyaGxZV1J6TDIxaAphVzR3R1FZS0t3WUJCQUdEdnpBQkR3UUxEQWsxTmpNMU1UQTVOVEl3TkFZS0t3WUJCQUdEdnpBQkVBUW1EQ1JvCmRIUndjem92TDJkcGRHaDFZaTVqYjIwdlkyaGhhVzVuZFdGeVpDMXBiV0ZuWlhNd0dRWUtLd1lCQkFHRHZ6QUIKRVFRTERBa3hNVE14T1RnMU5EVXdhZ1lLS3dZQkJBR0R2ekFCRWdSY0RGcG9kSFJ3Y3pvdkwyZHBkR2gxWWk1agpiMjB2WTJoaGFXNW5kV0Z5WkMxcGJXRm5aWE12YVcxaFoyVnpMeTVuYVhSb2RXSXZkMjl5YTJac2IzZHpMM0psCmJHVmhjMlV1ZVdGdGJFQnlaV1p6TDJobFlXUnpMMjFoYVc0d09BWUtLd1lCQkFHRHZ6QUJFd1FxRENnd01HVXkKTVdOak5EZzROR0l5Wm1FM01XSTVNbVU0TURVeE9URmpZV1JsTnpBNE1XRTNNakF4TUJRR0Npc0dBUVFCZzc4dwpBUlFFQmd3RWNIVnphREJlQmdvckJnRUVBWU8vTUFFVkJGQU1UbWgwZEhCek9pOHZaMmwwYUhWaUxtTnZiUzlqCmFHRnBibWQxWVhKa0xXbHRZV2RsY3k5cGJXRm5aWE12WVdOMGFXOXVjeTl5ZFc1ekx6WTFNVE15TURRek9UZ3YKWVhSMFpXMXdkSE12TVRBV0Jnb3JCZ0VFQVlPL01BRVdCQWdNQm5CMVlteHBZekNCaWdZS0t3WUJCQUhXZVFJRQpBZ1I4QkhvQWVBQjJBTjA5TUdyR3h4RXlZeGtlSEpsbk53S2lTbDY0M2p5dC80ZUtjb0F2S2U2T0FBQUJpeXJ5CmNWY0FBQVFEQUVjd1JRSWdJUTVnRlhoYTlvMm9qa2FabG9KNDV5Ymh5QjBNQU12ZU9JczJqcEZlMUtVQ0lRQzIKa2xyRm5zRjVPNEY3b0VNSFpOeHVNdm1vL1orZWNyVHRvYW5vdGsyYnBEQUtCZ2dxaGtqT1BRUURBd05uQURCawpBakJSTVJUMllnSG9HUVBYK2Y4OWhQSkdwcFlaVXMvVHdZMlFkbjdzVjN5MGxjMndpbmJYV2tzMDFhN0ZUNFNECnlJNENNR1YxRlVXNzhtR0dYU3dWQjJqMDJEd29aNEJNNVBnT3RVbmp4eHNPRElwbXpQK3g5c2crZUxESFhVeEcKUHFMMGZ3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	}
}`

func (s *sigment) rawBody() string {
	digest := s.statement.Digest.Identifier()
	_, hex, ok := strings.Cut(digest, ":")
	if !ok {
		panic("unexpected digest: " + digest)
	}
	payloadHash, _, err := v1.SHA256(bytes.NewReader(s.statement.Payload))
	if err != nil {
		panic(fmt.Errorf("computing statement payloadHash: %w", err))
	}
	return fmt.Sprintf(bodyTmpl, hex, payloadHash.Hex)
}
