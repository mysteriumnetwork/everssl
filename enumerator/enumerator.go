package enumerator

import (
	"context"
)

type Target struct {
	Domain string
	IPOverride string
}

type Enumerator interface {
	Enumerate(ctx context.Context, zone string, ipv6 bool) ([]Target, error)
}
