package heartbeat

import (
	"context"
	"log"
)

type LogHeartbeat struct{}

func NewLogHeartbeat() LogHeartbeat {
	return LogHeartbeat{}
}

func (b LogHeartbeat) Beat(ctx context.Context) error {
	log.Print("discadred heartbeat!")
	return nil
}
