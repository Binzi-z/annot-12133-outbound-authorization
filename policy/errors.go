package policy

import "errors"

// Service-level errors.
var (
	ErrBadGeneration     = errors.New("policy: snapshot generation must be strictly increasing")
	ErrUnknownGeneration = errors.New("policy: unknown generation for rollback")
)
