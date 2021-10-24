package validator

import (
	"context"

	"github.com/mysteriumnetwork/everssl/target"
)

type ValidationResult struct {
	Target target.Target
	Error  error
}

type Validator interface {
	Validate(context.Context, []target.Target) ([]ValidationResult, error)
}
