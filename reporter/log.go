package reporter

import (
	"context"
	"log"

	"github.com/mysteriumnetwork/everssl/validator/result"
)

type LogReporter struct {
}

func NewLogReporter() *LogReporter {
	return &LogReporter{}
}

func (r *LogReporter) Report(_ context.Context, results []result.ValidationResult) error {
	for _, res := range results {
		if res.Error != nil {
			log.Printf("Problem with domain %s (IP:%q): %v", res.Target.Domain, res.Target.Address, res.Error)
		}
	}

	return nil
}
