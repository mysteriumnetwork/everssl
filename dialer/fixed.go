package dialer

// Composable dialer which rewrites dials to particular fixed address and port

import (
	"context"
	"net"
)

type FixedDialer struct {
	address string
	port    string
	next    ContextDialer
}

// Use empty address or port value to retain original address or port part.
func NewFixedDialer(address, port string, next ContextDialer) *FixedDialer {
	return &FixedDialer{
		address: address,
		port:    port,
		next:    next,
	}
}

func (d *FixedDialer) DialContext(ctx context.Context, network, fullAddress string) (net.Conn, error) {
	addr, port, err := net.SplitHostPort(fullAddress)
	if err != nil {
		return nil, err
	}

	if d.address != "" {
		addr = d.address
	}

	if d.port != "" {
		port = d.port
	}

	return d.next.DialContext(ctx, network, net.JoinHostPort(addr, port))
}
