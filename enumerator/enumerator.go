package enumerator

import (
	"context"

	"github.com/mysteriumnetwork/everssl/target"
)

type Enumerator interface {
	Enumerate(ctx context.Context, zone string, ipv6 bool) ([]target.Target, error)
}
