// Package policy provides the loopback policy service used in tests.
//
// The service keeps the full history of published snapshots so tests can roll
// policy back to any earlier generation. Every time a snapshot is published the
// diff against the previous snapshot creates permanent tombstones; those
// tombstones are merged into every returned bundle regardless of generation,
// which is how rollback is prevented from restoring a revoked permission.
package policy

import (
	"sync"
	"time"
)

// Service is the in-memory loopback policy authority.
type Service struct {
	mu sync.RWMutex

	history    []Snapshot
	tombstones []Tombstone
	version    int64 // bumped on every change (publish or tombstone merge)
	notify     chan struct{}
}

// NewService seeds the service with an initial snapshot.
func NewService(initial Snapshot) *Service {
	svc := &Service{
		history: []Snapshot{{Generation: 0, Rules: nil}},
		notify:  make(chan struct{}, 1),
	}
	svc.Publish(initial)
	return svc
}

// Publish appends a snapshot. The new snapshot must have a strictly higher
// generation than the current head.
func (svc *Service) Publish(snap Snapshot) error {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	head := svc.history[len(svc.history)-1]
	if snap.Generation <= head.Generation {
		return ErrBadGeneration
	}
	for _, rev := range DiffRevoked(head, snap) {
		svc.tombstones = append(svc.tombstones, Tombstone{
			Tenant:       rev.Tenant,
			OriginalName: rev.Name,
			Generation:   snap.Generation,
			Reason:       rev.Reason,
			ObservedAt:   time.Now().UTC(),
		})
	}
	svc.history = append(svc.history, snap)
	svc.version++
	select {
	case svc.notify <- struct{}{}:
	default:
	}
	return nil
}

// Rollback republishes a previous generation as a NEW snapshot (with a fresh
// generation number). The older rules come back, but tombstones stay in force.
func (svc *Service) Rollback(generation int64) (Snapshot, error) {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	var target Snapshot
	for _, s := range svc.history {
		if s.Generation == generation {
			target = s
			break
		}
	}
	if target.Generation == 0 && len(target.Rules) == 0 {
		return Snapshot{}, ErrUnknownGeneration
	}
	next := svc.history[len(svc.history)-1].Generation + 1
	target.Generation = next
	svc.history = append(svc.history, target)
	svc.version++
	select {
	case svc.notify <- struct{}{}:
	default:
	}
	return target, nil
}

// Head returns the current snapshot.
func (svc *Service) Head() Snapshot {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	return svc.history[len(svc.history)-1]
}

// Tombstones returns a copy of all tombstones.
func (svc *Service) Tombstones() []Tombstone {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	return append([]Tombstone(nil), svc.tombstones...)
}

// Bundle returns the current decision bundle.
func (svc *Service) Bundle() Bundle {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	return Bundle{
		Snapshot:   svc.history[len(svc.history)-1],
		Tombstones: append([]Tombstone(nil), svc.tombstones...),
		Version:    svc.version,
	}
}

// Version returns the monotonic change version.
func (svc *Service) Version() int64 {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	return svc.version
}

// Notify returns a channel that receives one value when state changes.
// It is a 1-buffer coalescing signal: multiple changes may collapse.
func (svc *Service) Notify() <-chan struct{} { return svc.notify }

// History returns a copy of all published snapshots (for tests/inspection).
func (svc *Service) History() []Snapshot {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	return append([]Snapshot(nil), svc.history...)
}
