package heartbeat

import (
	"context"
)

type Heartbeat interface {
	Beat(context.Context) error
}
