package reporter

import (
	"context"
	"log"

	"github.com/mysteriumnetwork/everssl/validator/result"
)

type LogReporter struct {
	logOK bool
}

func NewLogReporter() *LogReporter {
	return &LogReporter{
		logOK: false,
	}
}

func (r *LogReporter) SetVerbose(verbose bool) *LogReporter {
	r.logOK = verbose
	return r
}

func (r *LogReporter) Report(_ context.Context, results []result.ValidationResult) error {
	for _, res := range results {
		if res.Error != nil {
			log.Printf("Problem with domain %s (Addr:%q): %v", res.Target.Domain, res.Target.Address, res.Error)
		} else if r.logOK {
			log.Printf("Domain %s (Addr:%q): OK", res.Target.Domain, res.Target.Address)
		}
	}

	return nil
}
