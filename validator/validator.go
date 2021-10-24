package validator

import (
	"context"

	"github.com/mysteriumnetwork/everssl/target"
)

type ValidationResult struct {
	Target target.Target
	Error  ValidationError
}

type Validator interface {
	Validate(context.Context, []target.Target) ([]ValidationResult, error)
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
