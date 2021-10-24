package reporter

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/PagerDuty/go-pagerduty"

	"github.com/mysteriumnetwork/everssl/validator/result"
)

type PagerDutyReporter struct {
	routingKey string
}

func NewPagerDutyReporter(routingKey string) *PagerDutyReporter {
	return &PagerDutyReporter{
		routingKey: routingKey,
	}
}

func (r *PagerDutyReporter) Report(ctx context.Context, results []result.ValidationResult) error {
	var resultErr error

	for _, res := range results {
		if res.Error == nil {
			continue
		}

		event := pagerduty.V2Event{
			RoutingKey: r.routingKey,
			Action: "trigger",
			DedupKey: fmt.Sprintf("%s/%s", res.Target.Domain, res.Target.IPOverride),
			Payload: &pagerduty.V2Payload{
				Summary: res.Error.Error(),
				Source: fmt.Sprintf("https://%s/", res.Target.Domain),
				Severity: "warning",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		}

		_, err := pagerduty.ManageEventWithContext(ctx, event)
		if err != nil {
			resultErr = multierror.Append(resultErr, err)
		}
	}

	return resultErr
}
