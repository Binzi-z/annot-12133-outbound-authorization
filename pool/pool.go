// Package pool is the sharded, identity-keyed multiplexed connection pool.
//
// Buckets are keyed by Identity.PoolKey() — a hash over the full identity tuple
// except ConnID. The pool therefore reuses connections ONLY between requests
// with identical tenant, policy generation, original name, resolution source,
// target and redirect chain. Two requests that resolve to the same TCP address
// but carry different identities hash to different buckets and can never share
// a mux session, so neither can borrow the other's trust context.
//
// Each shard has its own mutex so concurrent tenants contend independently.
package pool

import (
	"sync"
	"sync/atomic"

	"egressz/authz"
	"egressz/mux"
)

// Factory opens one new multiplexed session for the given identity.
type Factory func(id authz.Identity) (*mux.Session, error)

// Session wraps a pooled mux session with usage bookkeeping.
type Session struct {
	Mux       *mux.Session
	Key       string
	ConnID    string
	idleSince atomic.Int64
}

type bucket struct {
	entries []*Session // idle, reusable sessions (LRU-ish: append on return)
	created int
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

const defaultShards = 16

// Pool is the sharded pool.
type Pool struct {
	shards    [defaultShards]*shard
	factory   Factory
	maxPerKey int
}

// New builds a pool. maxPerKey caps live sessions per identity bucket.
func New(factory Factory, maxPerKey int) *Pool {
	p := &Pool{factory: factory, maxPerKey: maxPerKey}
	for i := range p.shards {
		p.shards[i] = &shard{buckets: map[string]*bucket{}}
	}
	return p
}

func (p *Pool) shardFor(key string) *shard {
	h := uint32(0)
	for i := 0; i < len(key); i++ {
		h = h*31 + uint32(key[i])
	}
	return p.shards[h%defaultShards]
}

// Get returns an existing reusable session for the identity, or calls the
// factory to open a new one. Borrowed sessions are removed from the idle list;
// callers must call Put when done. The bool is true when the session was
// borrowed from the idle bucket rather than newly established.
func (p *Pool) Get(id authz.Identity) (*Session, bool, error) {
	key := id.PoolKey()
	sh := p.shardFor(key)

	sh.mu.Lock()
	b := sh.buckets[key]
	if b == nil {
		b = &bucket{}
		sh.buckets[key] = b
	}
	if n := len(b.entries); n > 0 {
		sess := b.entries[n-1]
		b.entries = b.entries[:n-1]
		sh.mu.Unlock()
		return sess, true, nil
	}
	if b.created >= p.maxPerKey {
		sh.mu.Unlock()
		return nil, false, ErrPoolExhausted
	}
	b.created++
	sh.mu.Unlock()

	muxSess, err := p.factory(id)
	if err != nil {
		sh.mu.Lock()
		b.created--
		sh.mu.Unlock()
		return nil, false, err
	}
	return &Session{Mux: muxSess, Key: key, ConnID: muxSess.ConnID()}, false, nil
}

// Put returns a session to its bucket for reuse. A closed session is dropped.
func (p *Pool) Put(s *Session) {
	if s == nil {
		return
	}
	if s.Mux.Closed() {
		p.drop(s)
		return
	}
	sh := p.shardFor(s.Key)
	sh.mu.Lock()
	b := sh.buckets[s.Key]
	if b == nil {
		b = &bucket{}
		sh.buckets[s.Key] = b
	}
	if len(b.entries) >= p.maxPerKey {
		// Excess idle session: close rather than grow unbounded.
		oldest := b.entries[0]
		b.entries = b.entries[1:]
		_ = oldest.Mux.Close()
		b.created--
	}
	s.idleSince.Store(nowUnixNano())
	b.entries = append(b.entries, s)
	sh.mu.Unlock()
}

func (p *Pool) drop(s *Session) {
	sh := p.shardFor(s.Key)
	sh.mu.Lock()
	if b := sh.buckets[s.Key]; b != nil && b.created > 0 {
		b.created--
	}
	sh.mu.Unlock()
}

// CloseAll closes every pooled session (used on revocation and shutdown).
func (p *Pool) CloseAll() int {
	closed := 0
	for _, sh := range p.shards {
		sh.mu.Lock()
		for _, b := range sh.buckets {
			for _, s := range b.entries {
				_ = s.Mux.Close()
				closed++
			}
			b.entries = nil
			b.created = 0
		}
		sh.mu.Unlock()
	}
	return closed
}

// CloseKey closes every session belonging to one identity bucket and reports
// how many were closed. Used by abort-mode revocation.
func (p *Pool) CloseKey(key string) int {
	sh := p.shardFor(key)
	sh.mu.Lock()
	b := sh.buckets[key]
	closed := 0
	if b != nil {
		for _, s := range b.entries {
			_ = s.Mux.Close()
			closed++
		}
		b.entries = nil
		b.created = 0
	}
	sh.mu.Unlock()
	return closed
}

// Stats is a snapshot of pool occupancy.
type Stats struct {
	Buckets  int
	Idle     int
	Created  int
	PerShard [defaultShards]int
}

// Stats returns occupancy information for assertions and diagnostics.
func (p *Pool) Stats() Stats {
	var st Stats
	for i, sh := range p.shards {
		sh.mu.Lock()
		st.Buckets += len(sh.buckets)
		for _, b := range sh.buckets {
			st.Idle += len(b.entries)
			st.Created += b.created
			st.PerShard[i] += b.created
		}
		sh.mu.Unlock()
	}
	return st
}
