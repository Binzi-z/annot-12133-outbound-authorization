// Package barrier provides deterministic synchronization used to reproduce the
// race between an observed revocation and a new multiplexed stream open without
// relying on sleeps or wall-clock timing.
//
// A Barrier is a named rendezvous. One goroutine calls WaitFor to block until
// the named gate is opened by another goroutine via Open. Once a gate is open
// every WaitFor on that name returns immediately. All operations are
// deterministic: the test author chooses the exact interleaving.
package barrier

import (
	"sync"
)

type waiters struct {
	open bool
	ch   chan struct{}
}

// Barrier is a set of named, one-shot gates plus a per-name arrival counter.
type Barrier struct {
	mu     sync.Mutex
	gates  map[string]*waiters
	arrive map[string]int
}

// New creates an empty Barrier.
func New() *Barrier {
	return &Barrier{gates: map[string]*waiters{}, arrive: map[string]int{}}
}

func (b *Barrier) gateLocked(name string) *waiters {
	g, ok := b.gates[name]
	if !ok {
		g = &waiters{ch: make(chan struct{})}
		b.gates[name] = g
	}
	return g
}

// Open releases every goroutine waiting on name and leaves the gate open.
func (b *Barrier) Open(name string) {
	b.mu.Lock()
	g := b.gateLocked(name)
	if !g.open {
		g.open = true
		close(g.ch)
	}
	b.mu.Unlock()
}

// IsOpen reports whether the gate has been opened.
func (b *Barrier) IsOpen(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	g, ok := b.gates[name]
	return ok && g.open
}

// WaitFor blocks until name is opened.
func (b *Barrier) WaitFor(name string) {
	b.mu.Lock()
	g := b.gateLocked(name)
	ch := g.ch
	b.mu.Unlock()
	<-ch
}

// Arrive records that one goroutine reached name.
func (b *Barrier) Arrive(name string) {
	b.mu.Lock()
	b.arrive[name]++
	b.mu.Unlock()
}

// ArrivalCount returns how many times Arrive(name) was called.
func (b *Barrier) ArrivalCount(name string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.arrive[name]
}
