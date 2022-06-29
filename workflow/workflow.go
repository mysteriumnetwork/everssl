package workflow

import (
	"context"
	"fmt"

	"github.com/mysteriumnetwork/everssl/enumerator"
	"github.com/mysteriumnetwork/everssl/heartbeat"
	"github.com/mysteriumnetwork/everssl/reporter"
	"github.com/mysteriumnetwork/everssl/target"
	"github.com/mysteriumnetwork/everssl/validator"
	"github.com/mysteriumnetwork/everssl/validator/result"
)

type StringMatcher interface {
	MatchString(string) bool
}

type Runner struct {
	enumerator   enumerator.Enumerator
	domainFilter StringMatcher
	validator    validator.Validator
	drain        reporter.Reporter
	heartbeat    heartbeat.Heartbeat
}

func NewRunner(enum enumerator.Enumerator, filter StringMatcher, v validator.Validator, drain reporter.Reporter, beat heartbeat.Heartbeat) *Runner {
	return &Runner{
		enumerator:   enum,
		domainFilter: filter,
		validator:    v,
		drain:        drain,
		heartbeat:    beat,
	}
}

func (r *Runner) Run(ctx context.Context,
	zones []string,
	scanIPv6, ignoreConnectionErrors, ignoreHandshakeErrors, ignoreVerificationErrors, ignoreExpirationErrors bool,
) error {
	var targets []target.Target
	for _, zoneName := range zones {
		zoneTargets, err := r.enumerator.Enumerate(ctx, zoneName, scanIPv6)
		if err != nil {
			return fmt.Errorf("unable to enumerate targets for zone %s: %w", zoneName, err)
		}

		for _, target := range zoneTargets {
			if !r.domainFilter.MatchString(target.Domain) {
				targets = append(targets, target)
			}
		}
	}

	results, err := r.validator.Validate(ctx, targets)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	var filteredResults []result.ValidationResult
	for _, res := range results {
		if res.Error == nil {
			filteredResults = append(filteredResults, res)
		} else {
			switch res.Error.Kind() {
			case result.ConnectionError:
				if !ignoreConnectionErrors {
					filteredResults = append(filteredResults, res)
				}
			case result.HandshakeError:
				if !ignoreHandshakeErrors {
					filteredResults = append(filteredResults, res)
				}
			case result.VerificationError:
				if !ignoreVerificationErrors {
					filteredResults = append(filteredResults, res)
				}
			case result.ExpirationError:
				if !ignoreExpirationErrors {
					filteredResults = append(filteredResults, res)
				}
			default:
				filteredResults = append(filteredResults, res)
			}
		}
	}
	results = nil

	err = r.drain.Report(ctx, filteredResults)
	if err != nil {
		return fmt.Errorf("reporting error: %w", err)
	}

	err = r.heartbeat.Beat(ctx)
	if err != nil {
		return fmt.Errorf("heartbeat error: %w", err)
	}

	return nil
}
