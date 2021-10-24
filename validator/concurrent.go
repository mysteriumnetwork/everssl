package validator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"

	fixedDialer "github.com/mysteriumnetwork/everssl/dialer"
	"github.com/mysteriumnetwork/everssl/target"
)

const (
	Retries              = 3
	SingleAttemptTimeout = 5 * time.Second
)

type ConcurrentValidator struct {
	limiter            *rate.Limiter
	expirationTreshold time.Duration
	verify             bool
}

func NewConcurrentValidator(expirationTreshold, rateEvery time.Duration, verify bool) *ConcurrentValidator {
	limit := rate.Every(rateEvery)
	return &ConcurrentValidator{
		limiter:            rate.NewLimiter(limit, 1),
		expirationTreshold: expirationTreshold,
		verify:             verify,
	}
}

func (v *ConcurrentValidator) Validate(ctx context.Context, targets []target.Target) ([]ValidationResult, error) {
	var wg sync.WaitGroup
	results := make([]ValidationResult, len(targets))

	wg.Add(len(targets))
	for idx, t := range targets {
		go func(idx int, t target.Target) {
			defer wg.Done()

			err := v.validateSingle(ctx, t)
			results[idx] = ValidationResult{
				Target: t,
				Error:  err,
			}
		}(idx, t)
	}

	wg.Wait()
	return results, nil
}

func (v *ConcurrentValidator) validateSingle(ctx context.Context, target target.Target) error {
	var (
		conn net.Conn
		err  error
	)
	dialer := fixedDialer.NewFixedDialer(target.IPOverride, "", &net.Dialer{})

	for i := 0; i < Retries; i++ {
		err = v.limiter.Wait(ctx)
		if err != nil {
			return err
		}

		ctx1, cl := context.WithTimeout(ctx, SingleAttemptTimeout)
		defer cl()

		conn, err = dialer.DialContext(ctx1, "tcp", net.JoinHostPort(target.Domain, "443"))
		if err != nil {
			log.Printf("dialing error for target %+v: %v", target, err)
			continue
		}
		defer conn.Close()
	}

	if err != nil {
		return fmt.Errorf("all attempts failed. last error: %w", err)
	}

	var notAfter time.Time

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         target.Domain,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			notAfter = cs.PeerCertificates[0].NotAfter
			if v.verify {
				opts := x509.VerifyOptions{
					DNSName:       cs.ServerName,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			}
			return nil
		},
	})
	defer tlsConn.Close()

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return err
	}

	now := time.Now().Truncate(0)
	remainingDuration := notAfter.Sub(now)
	if remainingDuration < v.expirationTreshold {
		return fmt.Errorf("leaf certificate will be valid only for %v (treshold %v)",
			remainingDuration, v.expirationTreshold)
	}

	return nil
}
