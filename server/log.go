// Package server contains the loopback test infrastructure: the authoritative
// receive-log, the document origin service and the mux authorization proxy
// (including redirect proxies). Nothing here binds to a non-loopback address.
package server

import (
	"sync"
	"time"

	"egressz/authz"
	"egressz/policy"
)

// Entry is one authorization decision observed by a proxy when a mux stream
// presents its token. It is the server-side ground truth the reference model
// compares the sidecar's expectations against.
type Entry struct {
	Seq         int64           `json:"seq"`
	At          time.Time       `json:"at"`
	Proxy       string          `json:"proxy"`
	Decision    policy.Decision `json:"decision"`
	Reason      string          `json:"reason,omitempty"`
	Tenant      string          `json:"tenant"`
	Generation  int64           `json:"policy_generation"`
	Original    string          `json:"original_name"`
	Source      string          `json:"resolution_source"`
	Target      string          `json:"target"`
	ConnID      string          `json:"conn_id"`
	Fingerprint string          `json:"fingerprint"`
	Hops        []authz.Hop     `json:"hops"`
}

// DecisionLog is the append-only, thread-safe receive log.
type DecisionLog struct {
	mu      sync.Mutex
	entries []Entry
}

// NewDecisionLog creates an empty log.
func NewDecisionLog() *DecisionLog { return &DecisionLog{} }

// Record appends a decision and returns the stored entry.
func (l *DecisionLog) Record(proxy string, id authz.Identity, allowed bool, reason string) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	dec := policy.Deny
	if allowed {
		dec = policy.Allow
	}
	e := Entry{
		Seq:         int64(len(l.entries)) + 1,
		At:          time.Now().UTC(),
		Proxy:       proxy,
		Decision:    dec,
		Reason:      reason,
		Tenant:      id.Tenant,
		Generation:  id.PolicyGeneration,
		Original:    id.OriginalName,
		Source:      id.ResolutionSource,
		Target:      id.Target,
		ConnID:      id.ConnID,
		Fingerprint: id.Fingerprint(),
		Hops:        append([]authz.Hop(nil), id.Hops...),
	}
	l.entries = append(l.entries, e)
	return e
}

// Entries returns a copy of the log.
func (l *DecisionLog) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.entries...)
}

// ByFingerprint returns entries for one identity fingerprint.
func (l *DecisionLog) ByFingerprint(fp string) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Entry
	for _, e := range l.entries {
		if e.Fingerprint == fp {
			out = append(out, e)
		}
	}
	return out
}

// Allowed counts.
func (l *DecisionLog) Allowed() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if e.Decision == policy.Allow {
			n++
		}
	}
	return n
}

// Denied counts.
func (l *DecisionLog) Denied() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if e.Decision == policy.Deny {
			n++
		}
	}
	return n
}

// Reset clears the log.
func (l *DecisionLog) Reset() {
	l.mu.Lock()
	l.entries = nil
	l.mu.Unlock()
}
