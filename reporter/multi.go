package reporter

import (
	"context"

	"github.com/hashicorp/go-multierror"

	"github.com/mysteriumnetwork/everssl/validator/result"
)

type MultiReporter struct {
	reporters []Reporter
}

func NewMultiReporter(reporters ...Reporter) *MultiReporter {
	return &MultiReporter{
		reporters: reporters,
	}
}

func (r *MultiReporter) Report(ctx context.Context, results []result.ValidationResult) error {
	var result error

	for _, reporter := range r.reporters {
		if err := reporter.Report(ctx, results); err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result
}
