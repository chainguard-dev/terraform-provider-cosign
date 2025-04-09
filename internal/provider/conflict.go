package provider

import (
	"fmt"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant"
)

type conflictOp interface {
	secant.AttestConflictOp
	secant.SignConflictOp
}

func toConflictOp(conflict string) (conflictOp, error) {
	switch conflict {
	case "REPLACE":
		return secant.Replace, nil
	case "APPEND":
		return secant.Append, nil
	case "SKIPSAME":
		return secant.SkipSame, nil
	default:
		return nil, fmt.Errorf("invalid conflict %q", conflict)
	}
}
