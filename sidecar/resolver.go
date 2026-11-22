// Package sidecar contains the local egress authorization sidecar: name
// resolution with late-answer discard, fail-closed dialing, policy evaluation,
// the sharded mux pool, bounded retries, redirect-hop handling and the
// revocation boundary.
package sidecar

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// Resolution is one name-resolution answer.
type Resolution struct {
	Name   string
	Target string // dial address, e.g. "127.0.0.1:9101"
	Source string // resolver that produced the answer (part of identity)
}

// Resolver resolves names. A resolver may be slow; callers protect against
// stale answers through the generation token in ResolverTable.Resolve.
type Resolver interface {
	Resolve(ctx context.Context, name string) (Resolution, error)
	Source() string
}

// StaticResolver is the deterministic loopback resolver used by the reference
// model. It never touches the network or a public DNS.
type StaticResolver struct {
	source string
	mu     sync.RWMutex
	names  map[string]string
}

// NewStaticResolver builds an empty table under the given source label.
func NewStaticResolver(source string) *StaticResolver {
	return &StaticResolver{source: source, names: map[string]string{}}
}

// Set updates one name->target mapping.
func (r *StaticResolver) Set(name, target string) {
	r.mu.Lock()
	r.names[name] = target
	r.mu.Unlock()
}

// Source returns the resolver label carried in every identity.
func (r *StaticResolver) Source() string { return r.source }

// Resolve returns the current mapping.
func (r *StaticResolver) Resolve(_ context.Context, name string) (Resolution, error) {
	r.mu.RLock()
	target, ok := r.names[name]
	r.mu.RUnlock()
	if !ok {
		return Resolution{}, ErrUnknownName
	}
	return Resolution{Name: name, Target: target, Source: r.source}, nil
}

// ResolverTable wraps a Resolver and discards late answers: each request gets a
// monotonic token; when the request context is superseded (retry, redirect, or
// cancellation) the table bumps the token, and an answer arriving for an older
// token is dropped instead of being used to open a connection.
type ResolverTable struct {
	resolver Resolver
	token    atomic.Int64
}

// NewResolverTable wraps r.
func NewResolverTable(r Resolver) *ResolverTable {
	t := &ResolverTable{resolver: r}
	t.token.Store(1)
	return t
}

// Bump invalidates every outstanding resolution.
func (t *ResolverTable) Bump() { t.token.Add(1) }

// Resolve resolves name and only returns the answer if the token is still
// current. A late answer returns ErrLateResolution.
func (t *ResolverTable) Resolve(ctx context.Context, name string) (Resolution, int64, error) {
	token := t.token.Load()
	res, err := t.resolver.Resolve(ctx, name)
	if err != nil {
		return Resolution{}, token, err
	}
	if t.token.Load() != token {
		return Resolution{}, token, ErrLateResolution
	}
	return res, token, nil
}

// Common sidecar errors.
var (
	ErrUnknownName       = errors.New("sidecar: name not found in resolution table")
	ErrLateResolution    = errors.New("sidecar: resolution answer arrived too late and was discarded")
	ErrDenied            = errors.New("sidecar: authorization denied")
	ErrRevoked           = errors.New("sidecar: permission revoked, new requests forbidden")
	ErrNoPolicy          = errors.New("sidecar: no policy loaded, fail-closed")
	ErrDirectDialBlocked = errors.New("sidecar: direct dial blocked, no authorized egress path")
	ErrRetriesExhausted  = errors.New("sidecar: bounded retries exhausted")
	ErrTooManyRedirects  = errors.New("sidecar: redirect chain limit exceeded")
)
