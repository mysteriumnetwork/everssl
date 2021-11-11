package validator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"

	fixedDialer "github.com/mysteriumnetwork/everssl/dialer"
	"github.com/mysteriumnetwork/everssl/target"
	"github.com/mysteriumnetwork/everssl/validator/result"
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

func (v *ConcurrentValidator) Validate(ctx context.Context, targets []target.Target) ([]result.ValidationResult, error) {
	var wg sync.WaitGroup
	results := make([]result.ValidationResult, len(targets))

	wg.Add(len(targets))
	for idx, t := range targets {
		go func(idx int, t target.Target) {
			defer wg.Done()

			err := v.validateSingle(ctx, t)
			results[idx] = result.ValidationResult{
				Target: t,
				Error:  err,
			}
		}(idx, t)
	}

	wg.Wait()
	return results, nil
}

func (v *ConcurrentValidator) validateSingle(ctx context.Context, target target.Target) result.ValidationError {
	var (
		conn net.Conn
		err  error
	)
	dialer := fixedDialer.NewFixedDialer(target.Address, "", &net.Dialer{})

	for i := 0; i < Retries; i++ {
		err = v.limiter.Wait(ctx)
		if err != nil {
			return newValidationError(result.ConnectionError, fmt.Errorf("error waiting for ratelimit: %w", err))
		}

		ctx1, cl := context.WithTimeout(ctx, SingleAttemptTimeout)
		defer cl()

		conn, err = dialer.DialContext(ctx1, "tcp", net.JoinHostPort(target.Domain, "443"))
		if err != nil {
			continue
		}
		defer conn.Close()
	}

	if err != nil {
		return newValidationError(result.ConnectionError, fmt.Errorf("all attempts failed. last error: %w", err))
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
				if err != nil {
					return newValidationError(result.VerificationError, err)
				}
			}
			return nil
		},
	})
	defer tlsConn.Close()

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		switch e := err.(type) {
		case result.ValidationError:
			return e
		default:
			return newValidationError(result.HandshakeError, fmt.Errorf("handshake failed: %w", e))
		}
	}

	now := time.Now().Truncate(0)
	remainingDuration := notAfter.Sub(now)
	if remainingDuration < v.expirationTreshold {
		return newValidationError(result.ExpirationError, fmt.Errorf("leaf certificate will be valid only until %v", notAfter))
	}

	return nil
}

type validationError struct {
	wrapped error
	kind    result.ValidationErrorKind
}

func newValidationError(kind result.ValidationErrorKind, err error) *validationError {
	return &validationError{
		wrapped: err,
		kind:    kind,
	}
}

func (e *validationError) Error() string {
	return e.wrapped.Error()
}

func (e *validationError) Unwrap() error {
	return e.wrapped
}

func (e *validationError) Kind() result.ValidationErrorKind {
	return e.kind
}
