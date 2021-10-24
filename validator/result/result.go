package result

import (
	"github.com/mysteriumnetwork/everssl/target"
)

type ValidationResult struct {
	Target target.Target
	Error  ValidationError
}

type ValidationErrorKind int

const (
	ConnectionError   = ValidationErrorKind(iota)
	HandshakeError    = ValidationErrorKind(iota)
	VerificationError = ValidationErrorKind(iota)
	ExpirationError   = ValidationErrorKind(iota)
)

type ValidationError interface {
	error
	Unwrap() error
	Kind() ValidationErrorKind
}
