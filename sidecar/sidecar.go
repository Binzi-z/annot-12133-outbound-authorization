package sidecar

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"egressz/authz"
	"egressz/mux"
	"egressz/policy"
	"egressz/pool"
)

// MaxRedirectHops bounds how many redirects one request may follow.
const MaxRedirectHops = 3

// Config configures a Sidecar.
type Config struct {
	Secret       []byte
	MaxPerKey    int
	MaxRetries   int
	RevokeMode   RevokeMode
	Lease        time.Duration
	PolicyClient *policy.Client
	Resolver     Resolver
	Dialer       *GuardedDialer
	Hooks        Hooks
}

// inflight tracks one request already sent over a mux stream.
type inflight struct {
	tenant       string
	originalName string
	stream       *mux.Stream
	session      *pool.Session
}

// Sidecar is the local egress authorization sidecar.
type Sidecar struct {
	cfg      Config
	holder   *Holder
	resTable *ResolverTable
	pool     *pool.Pool

	mu       sync.Mutex
	inflight map[string]*inflight // keyed by request nonce

	metrics *Metrics
}

// Metrics counts sidecar outcomes for test assertions.
type Metrics struct {
	mu                  *sync.Mutex
	NewDenied           int
	RevokeBlocked       int
	InflightAborted     int
	LeaseExpired        int
	Retries             int
	LateDropped         int
	DirectDialBlocked   int
	RedirectsFollowed   int
	SessionsEstablished int
	SessionsBorrowed    int
}

func newMetrics() *Metrics {
	return &Metrics{mu: &sync.Mutex{}}
}

func (m *Metrics) inc(f func(*Metrics)) {
	m.mu.Lock()
	f(m)
	m.mu.Unlock()
}

// Snapshot returns a lock-free copy of the counters.
func (m *Metrics) Snapshot() Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *m
	cp.mu = nil
	return cp
}

// New builds a sidecar and starts its policy watch.
func New(ctx context.Context, cfg Config) (*Sidecar, error) {
	if cfg.MaxPerKey <= 0 {
		cfg.MaxPerKey = 4
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	s := &Sidecar{
		cfg:      cfg,
		resTable: NewResolverTable(cfg.Resolver),
		inflight: map[string]*inflight{},
		metrics:  newMetrics(),
	}
	// Wire observed-revocation side effects before the watch starts.
	if s.cfg.Hooks.OnRevoked == nil {
		s.cfg.Hooks.OnRevoked = s.ApplyRevocation
	} else {
		userHook := cfg.Hooks.OnRevoked
		s.cfg.Hooks.OnRevoked = func(rv Revocation) {
			userHook(rv)
			s.ApplyRevocation(rv)
		}
	}
	s.holder = NewHolder(cfg.PolicyClient, cfg.RevokeMode, cfg.Lease, s.cfg.Hooks)
	s.pool = pool.New(s.factory, cfg.MaxPerKey)
	if err := s.holder.Start(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Holder exposes the policy holder (e.g. for test assertions).
func (s *Sidecar) Holder() *Holder { return s.holder }

// Pool exposes pool stats.
func (s *Sidecar) Pool() *pool.Pool { return s.pool }

// Metrics returns a copy of the counters.
func (s *Sidecar) Metrics() Metrics {
	return s.metrics.Snapshot()
}

// Close stops the watcher and closes pooled sessions.
func (s *Sidecar) Close() error {
	s.holder.Stop()
	s.pool.CloseAll()
	return nil
}

// factory is injected into the pool: it dials through the guarded dialer and
// completes the mux client handshake. It NEVER dials an origin directly.
func (s *Sidecar) factory(id authz.Identity) (*mux.Session, error) {
	if !s.cfg.Dialer.Allowed(id.Target) {
		s.metrics.inc(func(m *Metrics) { m.DirectDialBlocked++ })
		return nil, fmt.Errorf("%w: %s", ErrDirectDialBlocked, id.Target)
	}
	conn, err := s.cfg.Dialer.Dial("tcp", id.Target)
	if err != nil {
		s.metrics.inc(func(m *Metrics) { m.DirectDialBlocked++ })
		return nil, err
	}
	connID := newConnID()
	sess, err := mux.Dial(conn, connID)
	if err != nil {
		conn.Close()
		return nil, err
	}
	s.metrics.inc(func(m *Metrics) { m.SessionsEstablished++ })
	return sess, nil
}

// Request is one egress request.
type Request struct {
	Tenant       string
	OriginalName string
	Body         []byte
}

// Response is the outcome visible to the local client.
type Response struct {
	Body       []byte
	Identity   authz.Identity
	Attempts   int
	Redirected int
	Nonce      string
}

// Do authorizes and executes one request, following redirects and bounded
// retries. Authorization failures are never retried; transport failures retry
// at most MaxRetries times with fresh resolutions and fresh sessions.
func (s *Sidecar) Do(ctx context.Context, req Request) (*Response, error) {
	// Hard boundary #1: no new request after observed revocation.
	if _, ok := s.holder.NewRequestAllowed(req.Tenant, req.OriginalName); !ok {
		s.metrics.inc(func(m *Metrics) {
			m.NewDenied++
			m.RevokeBlocked++
		})
		return nil, fmt.Errorf("%w: %s/%s", ErrRevoked, req.Tenant, req.OriginalName)
	}

	nonce := newNonce()
	hops := []authz.Hop(nil)
	targetName := req.OriginalName
	attempts := 0
	redirects := 0

	for {
		// Hard boundary re-checked on every attempt / hop: rollback never
		// restores an observed revocation.
		if _, ok := s.holder.NewRequestAllowed(req.Tenant, req.OriginalName); !ok {
			s.metrics.inc(func(m *Metrics) {
				m.NewDenied++
				m.RevokeBlocked++
			})
			return nil, fmt.Errorf("%w: %s/%s", ErrRevoked, req.Tenant, req.OriginalName)
		}

		// Late-resolution-safe lookup.
		resolution, _, rerr := s.resTable.Resolve(ctx, targetName)
		if rerr != nil {
			if errors.Is(rerr, ErrLateResolution) {
				s.metrics.inc(func(m *Metrics) { m.LateDropped++ })
			}
			return nil, rerr
		}

		id := authz.Identity{
			Tenant:           req.Tenant,
			PolicyGeneration: s.holder.Bundle().Snapshot.Generation,
			OriginalName:     req.OriginalName,
			ResolutionSource: resolution.Source,
			Target:           resolution.Target,
			Hops:             append([]authz.Hop(nil), hops...),
		}

		resp, retryable, rerr := s.attempt(ctx, req, id, nonce, bodyFor(hops, req.Body))
		if rerr == nil {
			return &Response{
				Body:       resp,
				Identity:   id,
				Attempts:   attempts + 1,
				Redirected: redirects,
				Nonce:      nonce,
			}, nil
		}

		if errors.Is(rerr, mux.ErrRedirected) {
			nextName := parseRedirectName(rerr)
			redirects++
			if redirects > MaxRedirectHops {
				return nil, ErrTooManyRedirects
			}
			// The hop records the address actually connected to on this leg;
			// the next leg re-resolves nextName to a new target.
			hops = append(hops, authz.Hop{
				From:    targetName,
				To:      nextName,
				Address: id.Target,
			})
			targetName = nextName
			s.metrics.inc(func(m *Metrics) { m.RedirectsFollowed++ })
			// Bump resolution token so any in-flight answer for the old name is late.
			s.resTable.Bump()
			continue
		}
		if !retryable || attempts >= s.cfg.MaxRetries {
			return nil, errors.Join(ErrRetriesExhausted, rerr)
		}
		attempts++
		s.metrics.inc(func(m *Metrics) { m.Retries++ })
		// Each retry uses a fresh resolution generation; stale answers drop.
		s.resTable.Bump()
	}
}

// attempt opens a pooled session bound to the identity, mints a connID-bound
// token, sends one request and reads one response.
func (s *Sidecar) attempt(ctx context.Context, req Request, id authz.Identity, nonce string, body []byte) ([]byte, bool, error) {
	if s.cfg.Hooks.OnPreOpen != nil {
		s.cfg.Hooks.OnPreOpen(id)
	}
	if s.cfg.Hooks.Barrier != nil {
		s.cfg.Hooks.Barrier.Arrive("preopen:" + id.Fingerprint())
		// Stable, tenant/name-scoped gate for deterministic tests.
		s.cfg.Hooks.Barrier.Arrive("preopen-key:" + req.Tenant + "/" + req.OriginalName)
	}

	sess, borrowed, err := s.pool.Get(id)
	if err != nil {
		return nil, true, err // pool exhaustion / dial failure: retryable
	}
	if borrowed {
		s.metrics.inc(func(m *Metrics) { m.SessionsBorrowed++ })
	}

	// The token's ConnID must equal the actual session's ConnID.
	id.ConnID = sess.ConnID
	tok := authz.MintToken(s.cfg.Secret, id, nonce)

	st, err := sess.Mux.Open()
	if err != nil {
		s.pool.Put(sess)
		return nil, true, err
	}
	if err := st.SendAuth(tok); err != nil {
		_ = st.Close()
		s.pool.Put(sess)
		return nil, true, err
	}

	// Register in-flight stream for abort/drain enforcement.
	in := &inflight{tenant: req.Tenant, originalName: req.OriginalName, stream: st, session: sess}
	nonceKey := nonce + ":" + id.Fingerprint()
	s.mu.Lock()
	s.inflight[nonceKey] = in
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.inflight, nonceKey)
		s.mu.Unlock()
	}()

	if _, err := st.Write(body); err != nil {
		s.pool.Put(sess)
		return nil, true, err
	}
	if err := st.CloseWrite(); err != nil {
		s.pool.Put(sess)
		return nil, true, err
	}

	// Check in-flight revocation boundary before blocking on the response.
	if ok, rv := s.holder.InFlightAllowed(req.Tenant, req.OriginalName); !ok {
		s.applyInflightRevocation(in, rv)
		return nil, false, fmt.Errorf("%w: %s", ErrRevoked, rv.Reason)
	}

	reply, rerr := io.ReadAll(st)
	if rerr == nil || errors.Is(rerr, io.EOF) {
		s.pool.Put(sess)
		return reply, false, nil
	}

	if errors.Is(rerr, mux.ErrRedirected) {
		s.pool.Put(sess)
		// Carry the redirect target through a typed error so Do can extend hops.
		return nil, false, &redirectError{target: st.RedirectTarget(), cause: rerr}
	}
	if errors.Is(rerr, mux.ErrStreamReset) {
		// Authz denial / server reset: do not retry authorization failures.
		_ = sess.Mux.Close()
		return nil, false, fmt.Errorf("%w: %s", ErrDenied, rerr.Error())
	}
	if errors.Is(rerr, mux.ErrSessionClosed) {
		// Abort-mode revocation closes the session out from under the stream.
		_ = sess.Mux.Close()
		return nil, false, fmt.Errorf("%w: session closed by revocation", ErrRevoked)
	}
	// Transport failure: close the bad session, signal retryable.
	_ = sess.Mux.Close()
	return nil, true, rerr
}

// applyInflightRevocation implements abort vs drain-with-lease for one stream.
func (s *Sidecar) applyInflightRevocation(in *inflight, rv Revocation) {
	s.metrics.inc(func(m *Metrics) {
		if s.holder.Mode() == RevokeAbort {
			m.InflightAborted++
		} else {
			m.LeaseExpired++
		}
	})
	_ = in.stream.Close()
	if s.holder.Mode() == RevokeAbort {
		s.pool.CloseKey(in.session.Key)
	} else {
		s.pool.Put(in.session)
	}
}

// ApplyRevocation is the observed-revocation side effect. In abort mode it
// closes every in-flight stream for the key and tears down its pooled sessions.
// In drain mode it pins each in-flight stream's read deadline to the lease
// boundary so a slow response cannot outlive the lease; new requests remain
// blocked by Holder.NewRequestAllowed regardless.
func (s *Sidecar) ApplyRevocation(rv Revocation) {
	s.mu.Lock()
	var victims []*inflight
	for _, in := range s.inflight {
		if in.tenant == rv.Tenant && in.originalName == rv.OriginalName {
			victims = append(victims, in)
		}
	}
	s.mu.Unlock()

	if s.holder.Mode() == RevokeAbort {
		keys := map[string]bool{}
		for _, in := range victims {
			_ = in.stream.Close()
			keys[in.session.Key] = true
		}
		for k := range keys {
			s.pool.CloseKey(k)
		}
		s.metrics.inc(func(m *Metrics) { m.InflightAborted += len(victims) })
		return
	}

	if rv.LeaseUntil.IsZero() {
		return
	}
	for _, in := range victims {
		_ = in.stream.SetReadDeadline(rv.LeaseUntil)
	}
}

// BumpResolution invalidates every outstanding resolution answer.
func (s *Sidecar) BumpResolution() { s.resTable.Bump() }

// ResolutionToken returns the current late-resolution generation token.
func (s *Sidecar) ResolutionToken() int64 { return s.resTable.token.Load() }

func newConnID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "conn-" + hex.EncodeToString(b)
}

func newNonce() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "req-" + hex.EncodeToString(b)
}

func bodyFor(hops []authz.Hop, body []byte) []byte {
	// The same document body is re-sent on each hop (idempotent PUT semantics).
	return append([]byte(nil), body...)
}

type redirectError struct {
	target string
	cause  error
}

func (e *redirectError) Error() string {
	return fmt.Sprintf("redirected to %s: %v", e.target, e.cause)
}
func (e *redirectError) Unwrap() error { return e.cause }
func (e *redirectError) Is(target error) bool {
	return target == mux.ErrRedirected
}

// parseRedirectName extracts the next name from a redirect error.
func parseRedirectName(err error) string {
	var re *redirectError
	if errors.As(err, &re) {
		return re.target
	}
	return ""
}
