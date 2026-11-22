package main

import (
	"context"
	"time"

	"egressz/client"
	"egressz/policy"
	"egressz/sidecar"
	"egressz/testsupport"
)

func doc(tenant, name string, rev int) client.Document {
	return client.Document{
		Tenant: tenant,
		Name:   name,
		Body:   "payload-" + name,
		Rev:    rev,
	}
}

func mustEnv(ctx context.Context, mode sidecar.RevokeMode, lease time.Duration, retries int) *testsupport.Topology {
	t, err := env(ctx, mode, lease, retries)
	if err != nil {
		panic(err)
	}
	return t
}

// waitForArrival blocks until the barrier saw at least n arrivals on gate.
func waitForArrival(t *testsupport.Topology, gate string, n int) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if t.Barrier.ArrivalCount(gate) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func expect(tenant, name string, d policy.Decision, reason string, hops int, proxies ...string) testsupport.Expectation {
	return testsupport.Expectation{
		Tenant: tenant, Original: name, Decision: d, ReasonSub: reason,
		Hops: hops, ProxyNames: proxies,
	}
}

// scenarioEstablish: fresh sessions for two tenants hitting the same address.
func scenarioEstablish(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeAbort, 0, 0)
	defer t.Close()
	r := &Report{}

	o1 := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 1))
	o2 := t.Sync.SyncOne(ctx, doc(testsupport.TenantB, testsupport.EdgeDoc, 1))
	r.note("tenantA outcome: %s", o1.String())
	r.note("tenantB outcome: %s", o2.String())

	m := t.Sidecar.Metrics()
	r.note("sessions established=%d borrowed=%d (want 2 established, 0 borrowed)",
		m.SessionsEstablished, m.SessionsBorrowed)
	r.note("both requests target %s but carry different tenant identities", t.EdgeProxy.Addr())
	r.Log = t.DecisionLog.Entries()

	wants := []testsupport.Expectation{
		expect(testsupport.TenantA, testsupport.EdgeDoc, policy.Allow, "", 0, "edge"),
		expect(testsupport.TenantB, testsupport.EdgeDoc, policy.Allow, "", 0, "edge"),
	}
	r.Mismatch = testsupport.Compare(t.DecisionLog, wants)
	r.OK = o1.OK && o2.OK && m.SessionsEstablished == 2 && m.SessionsBorrowed == 0 && len(r.Mismatch) == 0
	return r
}

// scenarioBorrow: same identity twice reuses (borrows) the pooled session.
func scenarioBorrow(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeAbort, 0, 0)
	defer t.Close()
	r := &Report{}

	o1 := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 1))
	firstConn := ""
	if fp := t.DecisionLog.Entries(); len(fp) > 0 {
		firstConn = fp[0].ConnID
	}
	o2 := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 2))
	r.note("request1: %s", o1.String())
	r.note("request2: %s", o2.String())

	conns := map[string]bool{}
	for _, e := range t.DecisionLog.Entries() {
		conns[e.ConnID] = true
	}
	m := t.Sidecar.Metrics()
	r.note("distinct server-observed connIDs=%d (want 1): %v", len(conns), keysOf(conns))
	r.note("established=%d borrowed=%d (want 1,1)", m.SessionsEstablished, m.SessionsBorrowed)
	r.note("first conn id reused: %v", firstConn != "" && conns[firstConn])
	r.Log = t.DecisionLog.Entries()

	wants := []testsupport.Expectation{
		expect(testsupport.TenantA, testsupport.EdgeDoc, policy.Allow, "", 0, "edge"),
	}
	r.Mismatch = testsupport.Compare(t.DecisionLog, wants)
	r.OK = o1.OK && o2.OK && len(conns) == 1 &&
		m.SessionsEstablished == 1 && m.SessionsBorrowed == 1 && len(r.Mismatch) == 0
	return r
}

// scenarioNoBorrowCrossIdentity: same dial address, different identity => no share.
func scenarioNoBorrowCrossIdentity(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeAbort, 0, 0)
	defer t.Close()
	r := &Report{}

	oa := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 1))
	ob := t.Sync.SyncOne(ctx, doc(testsupport.TenantB, testsupport.EdgeDoc, 1))
	oa2 := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 2))

	connsByTenant := map[string]map[string]bool{}
	for _, e := range t.DecisionLog.Entries() {
		if connsByTenant[e.Tenant] == nil {
			connsByTenant[e.Tenant] = map[string]bool{}
		}
		connsByTenant[e.Tenant][e.ConnID] = true
	}
	r.note("A ok=%v B ok=%v A2 ok=%v", oa.OK, ob.OK, oa2.OK)
	r.note("connIDs tenantA=%v tenantB=%v", keysOf(connsByTenant[testsupport.TenantA]),
		keysOf(connsByTenant[testsupport.TenantB]))
	shared := intersects(connsByTenant[testsupport.TenantA], connsByTenant[testsupport.TenantB])
	r.note("trust-context sharing across tenants detected: %v (want false)", shared)
	m := t.Sidecar.Metrics()
	r.note("pool stats: %+v", t.Sidecar.Pool().Stats())
	r.note("established=%d (want 2), borrowed=%d (A's second request borrows A only)",
		m.SessionsEstablished, m.SessionsBorrowed)
	r.Log = t.DecisionLog.Entries()

	wants := []testsupport.Expectation{
		expect(testsupport.TenantA, testsupport.EdgeDoc, policy.Allow, "", 0, "edge"),
		expect(testsupport.TenantB, testsupport.EdgeDoc, policy.Allow, "", 0, "edge"),
	}
	r.Mismatch = testsupport.Compare(t.DecisionLog, wants)
	r.OK = oa.OK && ob.OK && oa2.OK && !shared &&
		m.SessionsEstablished == 2 && len(r.Mismatch) == 0
	return r
}

// scenarioRedirect: one authorized redirect hop extends the identity chain.
func scenarioRedirect(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeAbort, 0, 1)
	defer t.Close()
	r := &Report{}

	o := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.RedirectDoc, 1))
	r.note("redirect request: %s", o.String())
	if o.OK {
		r.note("redirects followed=%d attempts=%d", o.Redirects, o.Attempts)
	}
	r.Log = t.DecisionLog.Entries()
	// First leg lands on the redirect proxy with 0 hops; after following the
	// redirect the edge proxy authorizes a 1-hop extended identity.
	redirHops, edgeHops := map[int]bool{}, map[int]bool{}
	for _, e := range r.Log {
		if e.Original != testsupport.RedirectDoc {
			continue
		}
		if e.Proxy == "redirect-hop" {
			redirHops[len(e.Hops)] = true
		}
		if e.Proxy == "edge" {
			edgeHops[len(e.Hops)] = true
		}
	}
	r.note("redirect-hop counts=%v (must contain 0); edge counts=%v (must contain 1)",
		redirHops, edgeHops)

	wants := []testsupport.Expectation{
		{Tenant: testsupport.TenantA, Original: testsupport.RedirectDoc,
			Decision: policy.Allow, Hops: 0, ProxyNames: []string{"redirect-hop"}},
		{Tenant: testsupport.TenantA, Original: testsupport.RedirectDoc,
			Decision: policy.Allow, Hops: 1, ProxyNames: []string{"edge"}},
	}
	r.Mismatch = testsupport.Compare(t.DecisionLog, wants)
	r.OK = o.OK && o.Redirects >= 1 && redirHops[0] && edgeHops[1] && len(r.Mismatch) == 0
	return r
}

// scenarioDeny: tenant B is not allowed on the redirect document.
func scenarioDeny(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeAbort, 0, 0)
	defer t.Close()
	r := &Report{}

	o := t.Sync.SyncOne(ctx, doc(testsupport.TenantB, testsupport.RedirectDoc, 1))
	r.note("denied request: %s", o.String())
	r.note("retries=%d (authz denial must not be retried)", t.Sidecar.Metrics().Retries)
	r.Log = t.DecisionLog.Entries()

	wants := []testsupport.Expectation{
		expect(testsupport.TenantB, testsupport.RedirectDoc, policy.Deny,
			"rule_denied", 0, "redirect-hop"),
	}
	r.Mismatch = testsupport.Compare(t.DecisionLog, wants)
	r.OK = !o.OK && t.Sidecar.Metrics().Retries == 0 && len(r.Mismatch) == 0
	return r
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, shortID(k))
	}
	return out
}

func intersects(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}
