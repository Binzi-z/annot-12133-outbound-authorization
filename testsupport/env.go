// Package testsupport wires the complete loopback reference topology used by
// both the executable reference model and the Go tests:
//
//	policy service (loopback HTTP)
//	origin service   (loopback TCP)
//	edge / redirect authz proxies (loopback mux)
//	sidecar          (in-process, guarded loopback dialer)
//	sync client      (in-process)
//
// No component binds a non-loopback address and no component dials one.
package testsupport

import (
	"context"
	"net/http/httptest"
	"time"

	"egressz/barrier"
	"egressz/client"
	"egressz/policy"
	"egressz/server"
	"egressz/sidecar"
)

// Topology is one fully-wired loopback deployment.
type Topology struct {
	Secret []byte

	PolicySvc    *policy.Service
	PolicyHTTP   *httptest.Server
	PolicyClient *policy.Client

	Origin      *server.Origin
	DecisionLog *server.DecisionLog
	EdgeProxy   *server.AuthzProxy
	RedirectPrx *server.AuthzProxy

	Resolver *sidecar.StaticResolver
	Dialer   *sidecar.GuardedDialer
	Barrier  *barrier.Barrier
	Sidecar  *sidecar.Sidecar
	Sync     *client.SyncClient

	initial policy.Snapshot
}

// Config controls topology construction.
type Config struct {
	RevokeMode sidecar.RevokeMode
	Lease      time.Duration
	MaxRetries int
	MaxPerKey  int
	Initial    policy.Snapshot
}

// Standup starts every component and returns a ready topology.
func Standup(ctx context.Context, cfg Config) (*Topology, error) {
	t := &Topology{
		Secret:      []byte("loopback-reference-secret"),
		DecisionLog: server.NewDecisionLog(),
		Barrier:     barrier.New(),
		initial:     cfg.Initial,
	}

	// Policy authority over loopback HTTP.
	t.PolicySvc = policy.NewService(cfg.Initial)
	t.PolicyHTTP = httptest.NewServer(t.PolicySvc)
	t.PolicyClient = policy.NewClient(t.PolicyHTTP.URL)

	// Loopback origin.
	origin, err := server.NewOrigin()
	if err != nil {
		return nil, err
	}
	t.Origin = origin

	// Redirect proxy first so the edge proxy name can be referenced.
	redir, err := server.NewAuthzProxy(server.ProxyConfig{
		Name:       "redirect-hop",
		Secret:     t.Secret,
		Log:        t.DecisionLog,
		RedirectTo: "edge-doc",
	})
	if err != nil {
		return nil, err
	}
	t.RedirectPrx = redir

	edge, err := server.NewAuthzProxy(server.ProxyConfig{
		Name:   "edge",
		Secret: t.Secret,
		Log:    t.DecisionLog,
		Origin: origin.Addr(),
	})
	if err != nil {
		return nil, err
	}
	t.EdgeProxy = edge

	// Name resolution is a static loopback table (no DNS, no public network).
	// redirect-doc's first leg lands on the redirect proxy, which redirects to
	// edge-doc; the second leg is authorized at the edge proxy and forwarded.
	t.Resolver = sidecar.NewStaticResolver("static-loopback-v1")
	t.Resolver.Set("edge-doc", edge.Addr())
	t.Resolver.Set("redirect-doc", redir.Addr())

	// The guarded dialer knows every loopback proxy address and nothing else.
	t.Dialer = sidecar.NewGuardedDialer(edge.Addr(), redir.Addr())

	hooks := sidecar.Hooks{Barrier: t.Barrier}
	sc, err := sidecar.New(ctx, sidecar.Config{
		Secret:       t.Secret,
		MaxPerKey:    cfg.MaxPerKey,
		MaxRetries:   cfg.MaxRetries,
		RevokeMode:   cfg.RevokeMode,
		Lease:        cfg.Lease,
		PolicyClient: t.PolicyClient,
		Resolver:     t.Resolver,
		Dialer:       t.Dialer,
		Hooks:        hooks,
	})
	if err != nil {
		return nil, err
	}
	t.Sidecar = sc
	t.Sync = client.New(sc)

	// Push the initial bundle to both decision points.
	t.PushBundle(t.PolicySvc.Bundle())
	return t, nil
}

// PushBundle makes every server-side decision point use the given bundle.
func (t *Topology) PushBundle(b policy.Bundle) {
	t.EdgeProxy.SetBundle(b)
	t.RedirectPrx.SetBundle(b)
}

// Publish pushes a new snapshot through the service, waits for the sidecar
// watch to observe it, and refreshes every proxy bundle.
func (t *Topology) Publish(ctx context.Context, snap policy.Snapshot) (policy.Bundle, error) {
	b, err := t.PolicyClient.Publish(snap)
	if err != nil {
		return policy.Bundle{}, err
	}
	if err := t.waitForVersion(ctx, b.Version); err != nil {
		return policy.Bundle{}, err
	}
	t.PushBundle(b)
	return b, nil
}

// Rollback asks the service to re-publish an older generation, then propagates.
func (t *Topology) Rollback(ctx context.Context, generation int64) (policy.Bundle, error) {
	if _, err := t.PolicyClient.Rollback(generation); err != nil {
		return policy.Bundle{}, err
	}
	b := t.PolicySvc.Bundle()
	if err := t.waitForVersion(ctx, b.Version); err != nil {
		return policy.Bundle{}, err
	}
	t.PushBundle(b)
	return b, nil
}

func (t *Topology) waitForVersion(ctx context.Context, want int64) error {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if t.Sidecar.Holder().Bundle().Version >= want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return errWaitTimeout
}

// Close releases every component.
func (t *Topology) Close() {
	if t.Sidecar != nil {
		_ = t.Sidecar.Close()
	}
	if t.PolicyHTTP != nil {
		t.PolicyHTTP.Close()
	}
	_ = t.EdgeProxy.Close()
	_ = t.RedirectPrx.Close()
	_ = t.Origin.Close()
}
