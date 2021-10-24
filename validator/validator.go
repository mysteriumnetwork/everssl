package validator

import (
	"context"

	"github.com/mysteriumnetwork/everssl/target"
	"github.com/mysteriumnetwork/everssl/validator/result"
)

type Validator interface {
	Validate(context.Context, []target.Target) ([]result.ValidationResult, error)
}
