package sidecar

import (
	"context"
	"sync"
	"time"

	"egressz/authz"
	"egressz/barrier"
	"egressz/policy"
)

// RevokeMode controls what happens to requests already in flight when a
// revocation is observed.
type RevokeMode string

const (
	// RevokeAbort terminates in-flight requests immediately and closes every
	// pooled session for the revoked identity.
	RevokeAbort RevokeMode = "abort"
	// RevokeDrain lets in-flight requests finish, but only until their lease
	// expires; new requests are still forbidden.
	RevokeDrain RevokeMode = "drain"
)

// Revocation is one observed revocation boundary.
type Revocation struct {
	Tenant       string
	OriginalName string
	Generation   int64
	Reason       string
	ObservedAt   time.Time
	LeaseUntil   time.Time // zero in abort mode
}

// Key matches policy.PermissionKey.
func (r Revocation) Key() string { return r.Tenant + "\x00" + r.OriginalName }

// LeaseExpired reports whether an in-flight drain request must now be aborted.
func (r Revocation) LeaseExpired(now time.Time) bool {
	return !r.LeaseUntil.IsZero() && now.After(r.LeaseUntil)
}

// Hooks are deterministic rendezvous points used by tests. All may be nil.
type Hooks struct {
	Barrier *barrier.Barrier
	// OnRevoked fires after a revocation has been applied to local state.
	OnRevoked func(Revocation)
	// OnPreOpen fires immediately before opening a mux stream (race window).
	OnPreOpen func(authz.Identity)
}

// Holder is the sidecar's local policy state. It watches the policy service,
// applies bundles, records observed revocations and enforces the boundary:
//
//   - after observation, NewRequestAllowed returns false forever for that key;
//   - InFlightAllowed implements abort vs. drain-with-lease semantics.
type Holder struct {
	mu      sync.RWMutex
	bundle  policy.Bundle
	loaded  bool
	revokes map[string]Revocation

	mode      RevokeMode
	lease     time.Duration
	pc        *policy.Client
	hooks     Hooks
	stopWatch context.CancelFunc
	wg        sync.WaitGroup

	now func() time.Time
}

// NewHolder builds a holder. lease is only meaningful in drain mode.
func NewHolder(pc *policy.Client, mode RevokeMode, lease time.Duration, hooks Hooks) *Holder {
	return &Holder{
		revokes: map[string]Revocation{},
		mode:    mode,
		lease:   lease,
		pc:      pc,
		hooks:   hooks,
		now:     time.Now,
	}
}

// Start performs the initial load (fail-closed on failure) and begins watching.
func (h *Holder) Start(ctx context.Context) error {
	b, err := h.pc.Bundle()
	if err != nil {
		// Fail closed: stay unloaded and deny everything rather than allow.
		return err
	}
	h.applyBundle(b)
	subCtx, cancel := context.WithCancel(ctx)
	h.stopWatch = cancel
	h.wg.Add(1)
	go h.watchLoop(subCtx, b.Version)
	return nil
}

// Stop ends the watch goroutine.
func (h *Holder) Stop() {
	if h.stopWatch != nil {
		h.stopWatch()
	}
	h.wg.Wait()
}

func (h *Holder) watchLoop(ctx context.Context, from int64) {
	defer h.wg.Done()
	_ = h.pc.Watch(ctx, from, func(b policy.Bundle) {
		h.applyBundle(b)
	})
}

// applyBundle swaps in the bundle and derives revocations from new tombstones.
func (h *Holder) applyBundle(b policy.Bundle) {
	h.mu.Lock()
	h.bundle = b
	h.loaded = true
	known := map[string]bool{}
	for k := range h.revokes {
		known[k] = true
	}
	now := h.now()
	applied := make([]Revocation, 0)
	for _, t := range b.Tombstones {
		if known[t.Key()] {
			continue
		}
		rv := Revocation{
			Tenant:       t.Tenant,
			OriginalName: t.OriginalName,
			Generation:   t.Generation,
			Reason:       t.Reason,
			ObservedAt:   now,
		}
		if h.mode == RevokeDrain {
			rv.LeaseUntil = now.Add(h.lease)
		}
		h.revokes[t.Key()] = rv
		applied = append(applied, rv)
	}
	h.mu.Unlock()

	if h.hooks.OnRevoked != nil {
		for _, rv := range applied {
			h.hooks.OnRevoked(rv)
		}
	}
	if h.hooks.Barrier != nil {
		for _, rv := range applied {
			h.hooks.Barrier.Arrive("revoked:" + rv.Key())
		}
	}
}

// Bundle returns the current policy bundle (for local evaluation).
func (h *Holder) Bundle() policy.Bundle {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.bundle
}

// Loaded reports whether initial policy was received.
func (h *Holder) Loaded() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.loaded
}

// NewRequestAllowed enforces the hard boundary: once a revocation for this key
// has been observed, no new request may be issued, regardless of later policy
// generations (rollback included).
func (h *Holder) NewRequestAllowed(tenant, originalName string) (policy.Result, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if !h.loaded {
		return policy.Result{Decision: policy.Deny, Reason: "no_policy_loaded"}, false
	}
	key := policy.PermissionKey(tenant, originalName)
	if rv, ok := h.revokes[key]; ok {
		return policy.Result{
			Decision:   policy.Deny,
			Reason:     "revoked:" + rv.Reason,
			Generation: h.bundle.Snapshot.Generation,
		}, false
	}
	id := authz.Identity{Tenant: tenant, OriginalName: originalName}
	res := policy.Evaluate(h.bundle, id)
	return res, res.Decision == policy.Allow
}

// InFlightAllowed checks whether a request already sent may continue.
// Abort mode kills immediately; drain mode allows until the lease expires.
func (h *Holder) InFlightAllowed(tenant, originalName string) (bool, Revocation) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	rv, ok := h.revokes[policy.PermissionKey(tenant, originalName)]
	if !ok {
		return true, Revocation{}
	}
	if h.mode == RevokeAbort {
		return false, rv
	}
	if rv.LeaseExpired(h.now()) {
		return false, rv
	}
	return true, rv
}

// Revocation returns the recorded revocation for a key, if observed.
func (h *Holder) Revocation(key string) (Revocation, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	rv, ok := h.revokes[key]
	return rv, ok
}

// Mode returns the configured revocation mode.
func (h *Holder) Mode() RevokeMode { return h.mode }
