package reporter

import (
	"context"

	"github.com/mysteriumnetwork/everssl/validator/result"
)

type Reporter interface {
	Report(ctx context.Context, results []result.ValidationResult) error
}
