package sidecar

import "fmt"

// Guard errors carry the offending address so tests can assert the block.
type guardError struct {
	kind    string
	address string
}

func (e *guardError) Error() string {
	return fmt.Sprintf("sidecar: %s: %s", e.kind, e.address)
}

// Is reports guard failures as ErrDirectDialBlocked so callers can treat the
// allowlist and loopback checks uniformly as fail-closed dial refusals.
func (e *guardError) Is(target error) bool {
	return target == ErrDirectDialBlocked
}

// ErrDirectDialedGuard wraps the fail-closed dial error with the address.
func ErrDirectDialedGuard(address string) error {
	return &guardError{kind: "address not in egress allowlist", address: address}
}

// ErrNonLoopback refuses anything outside loopback; the reference model never
// accesses the public network.
func ErrNonLoopback(address string) error {
	return &guardError{kind: "non-loopback destination refused", address: address}
}
