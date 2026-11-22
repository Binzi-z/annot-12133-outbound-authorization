package testsupport_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"egressz/client"
	"egressz/policy"
	"egressz/sidecar"
	"egressz/testsupport"
)

func TestTwoTenantEstablishAndBorrow(t *testing.T) {
	ctx := context.Background()
	top, err := testsupport.Standup(ctx, testsupport.Config{
		RevokeMode: sidecar.RevokeAbort, MaxPerKey: 4, Initial: testsupport.InitialSnapshot(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer top.Close()

	a1 := top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc})
	b1 := top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantB, Name: testsupport.EdgeDoc})
	a2 := top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc})
	if !a1.OK || !b1.OK || !a2.OK {
		t.Fatalf("all three should succeed: %+v %+v %+v", a1, b1, a2)
	}
	mm := testsupport.Compare(top.DecisionLog, []testsupport.Expectation{
		{Tenant: testsupport.TenantA, Original: testsupport.EdgeDoc, Decision: policy.Allow, ProxyNames: []string{"edge"}},
		{Tenant: testsupport.TenantB, Original: testsupport.EdgeDoc, Decision: policy.Allow, ProxyNames: []string{"edge"}},
	})
	if len(mm) != 0 {
		t.Fatalf("receive-log mismatch: %+v", mm)
	}
	m := top.Sidecar.Metrics()
	if m.SessionsEstablished != 2 || m.SessionsBorrowed != 1 {
		t.Fatalf("want 2 establishes and 1 borrow, got %+v", m)
	}
	// Tenant connection sets must be disjoint.
	conns := map[string]map[string]bool{}
	for _, e := range top.DecisionLog.Entries() {
		if conns[e.Tenant] == nil {
			conns[e.Tenant] = map[string]bool{}
		}
		conns[e.Tenant][e.ConnID] = true
	}
	for k := range conns[testsupport.TenantA] {
		if conns[testsupport.TenantB][k] {
			t.Fatal("cross-tenant connection sharing detected")
		}
	}
}

func TestRedirectChainReauthorized(t *testing.T) {
	ctx := context.Background()
	top, err := testsupport.Standup(ctx, testsupport.Config{
		RevokeMode: sidecar.RevokeAbort, MaxRetries: 2, Initial: testsupport.InitialSnapshot(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer top.Close()

	o := top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantA, Name: testsupport.RedirectDoc})
	if !o.OK || o.Redirects < 1 {
		t.Fatalf("redirect flow failed: %+v", o)
	}
	// First leg: redirect proxy sees the initial identity (0 hops). Second
	// leg: edge proxy sees an identity extended with one hop.
	redirHops, edgeHops := map[int]bool{}, map[int]bool{}
	for _, e := range top.DecisionLog.Entries() {
		if e.Original != testsupport.RedirectDoc {
			continue
		}
		switch e.Proxy {
		case "redirect-hop":
			redirHops[len(e.Hops)] = true
		case "edge":
			edgeHops[len(e.Hops)] = true
		}
	}
	if !redirHops[0] || !edgeHops[1] {
		t.Fatalf("hop chain wrong: redirect-hop seen=%v edge seen=%v",
			redirHops, edgeHops)
	}
}

func TestRevocationAbortAndRollback(t *testing.T) {
	ctx := context.Background()
	top, err := testsupport.Standup(ctx, testsupport.Config{
		RevokeMode: sidecar.RevokeAbort, Initial: testsupport.InitialSnapshot(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer top.Close()

	before := top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc})
	if !before.OK {
		t.Fatal(before.Error)
	}
	if _, err := top.Publish(ctx, testsupport.SnapshotRevokeA()); err != nil {
		t.Fatal(err)
	}
	after := top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc})
	if after.OK {
		t.Fatal("new request after observed revocation must be blocked")
	}
	// Rollback restores the rule but the tombstone must keep denying.
	if _, err := top.Rollback(ctx, 1); err != nil {
		t.Fatal(err)
	}
	rolled := top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc})
	if rolled.OK {
		t.Fatal("rollback must not restore a revoked permission")
	}
	allows := 0
	for _, e := range top.DecisionLog.Entries() {
		if e.Tenant == testsupport.TenantA && e.Original == testsupport.EdgeDoc && e.Decision == policy.Allow {
			allows++
		}
	}
	if allows != 1 {
		t.Fatalf("want exactly one pre-revocation ALLOW, got %d", allows)
	}
}

func TestDrainLeaseBoundary(t *testing.T) {
	ctx := context.Background()
	top, err := testsupport.Standup(ctx, testsupport.Config{
		RevokeMode: sidecar.RevokeDrain, Lease: 80 * time.Millisecond,
		Initial: testsupport.InitialSnapshot(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer top.Close()
	top.Origin.SetDelay(400 * time.Millisecond)

	ch := make(chan client.Outcome, 1)
	go func() {
		ch <- top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc})
	}()
	waitFor(t, "preopen-key:"+testsupport.TenantA+"/"+testsupport.EdgeDoc, top, 1)
	if _, err := top.Publish(ctx, testsupport.SnapshotRevokeA()); err != nil {
		t.Fatal(err)
	}
	o := <-ch
	if o.OK {
		t.Fatal("in-flight request past lease expiry must be aborted")
	}
}

func TestFailClosedNoPolicyAndNoDirectDial(t *testing.T) {
	ctx := context.Background()
	top, err := testsupport.Standup(ctx, testsupport.Config{
		RevokeMode: sidecar.RevokeAbort, Initial: testsupport.InitialSnapshot(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer top.Close()

	top.Resolver.Set("ghost", "127.0.0.1:9")
	o := top.Sync.SyncOne(ctx, client.Document{Tenant: testsupport.TenantA, Name: "ghost"})
	if o.OK {
		t.Fatal("un-allowlisted target must fail, never direct-dial")
	}
}

func TestProxyListenerLocalHTTP(t *testing.T) {
	ctx := context.Background()
	top, err := testsupport.Standup(ctx, testsupport.Config{
		RevokeMode: sidecar.RevokeAbort, Initial: testsupport.InitialSnapshot(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer top.Close()

	pl, err := sidecar.ServeProxy(top.Sidecar)
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()

	req, _ := http.NewRequest(http.MethodPost,
		"http://"+pl.Addr()+"/egress",
		bytes.NewReader([]byte(`{"tenant":"x"}`)))
	req.Header.Set(sidecar.HeaderTenant, testsupport.TenantA)
	req.Header.Set(sidecar.HeaderDoc, testsupport.EdgeDoc)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Egress-Fingerprint") == "" {
		t.Fatalf("local proxy must return an authorized fingerprint, status=%d", resp.StatusCode)
	}

	// A post-revocation request through the same listener is refused.
	if _, err := top.Publish(ctx, testsupport.SnapshotRevokeA()); err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest(http.MethodPost,
		"http://"+pl.Addr()+"/egress", bytes.NewReader([]byte(`{}`)))
	req2.Header.Set(sidecar.HeaderTenant, testsupport.TenantA)
	req2.Header.Set(sidecar.HeaderDoc, testsupport.EdgeDoc)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked request must be 403, got %d", resp2.StatusCode)
	}
}

func waitFor(t *testing.T, gate string, top *testsupport.Topology, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if top.Barrier.ArrivalCount(gate) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("barrier gate %s never reached %d arrivals", gate, n)
}
