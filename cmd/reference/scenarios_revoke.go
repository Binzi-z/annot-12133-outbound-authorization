package main

import (
	"context"
	"time"

	"egressz/client"
	"egressz/policy"
	"egressz/server"
	"egressz/sidecar"
	"egressz/testsupport"
)

const (
	gateGo         = "race:go"
	preopenKeyGate = "preopen-key:"
	revokedKeyGate = "revoked:"
)

func preopenKey(tenant, name string) string { return preopenKeyGate + tenant + "/" + name }

func revokedKey(tenant, name string) string {
	return revokedKeyGate + policy.PermissionKey(tenant, name)
}

func countAllows(entries []server.Entry, tenant, name string) int {
	n := 0
	for _, e := range entries {
		if e.Tenant == tenant && e.Original == name && e.Decision == policy.Allow {
			n++
		}
	}
	return n
}

// scenarioRevokeAbort: revocation observed => new blocked, in-flight aborted.
func scenarioRevokeAbort(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeAbort, 0, 0)
	defer t.Close()
	r := &Report{}

	before := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 1))
	r.note("before revoke: %s", before.String())

	if _, err := t.Publish(ctx, testsupport.SnapshotRevokeA()); err != nil {
		r.note("publish error: %v", err)
		return r
	}
	rv, ok := t.Sidecar.Holder().Revocation(
		policy.PermissionKey(testsupport.TenantA, testsupport.EdgeDoc))
	r.note("revocation observed: ok=%v gen=%d reason=%s mode=%s",
		ok, rv.Generation, rv.Reason, t.Sidecar.Holder().Mode())

	after := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 2))
	tenantB := t.Sync.SyncOne(ctx, doc(testsupport.TenantB, testsupport.EdgeDoc, 1))
	r.note("after revoke new request ok=%v (want false); tenantB ok=%v (want true)",
		after.OK, tenantB.OK)

	m := t.Sidecar.Metrics()
	r.note("metrics revokeBlocked=%d inflightAborted=%d", m.RevokeBlocked, m.InflightAborted)
	r.Log = t.DecisionLog.Entries()
	r.note("origin received %d request bodies", len(t.Origin.Received()))

	allows := countAllows(r.Log, testsupport.TenantA, testsupport.EdgeDoc)
	r.note("tenantA edge ALLOW entries=%d (want exactly 1, the pre-revocation one)", allows)
	r.OK = before.OK && !after.OK && tenantB.OK && allows == 1
	return r
}

// scenarioRevokeDrain: an in-flight request finishes within its lease while new
// requests are still forbidden.
func scenarioRevokeDrain(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeDrain, time.Second, 0)
	t.Origin.SetDelay(150 * time.Millisecond)
	defer t.Close()
	r := &Report{}

	inflightCh := make(chan client.Outcome, 1)
	go func() {
		inflightCh <- t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 1))
	}()
	waitForArrival(t, preopenKey(testsupport.TenantA, testsupport.EdgeDoc), 1)

	if _, err := t.Publish(ctx, testsupport.SnapshotRevokeA()); err != nil {
		r.note("publish error: %v", err)
		return r
	}
	r.note("revocation observed while request in flight (drain, lease 1s, delay 150ms)")

	inflight := <-inflightCh
	after := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 2))
	r.note("in-flight result ok=%v (want true, inside lease); new request ok=%v (want false)",
		inflight.OK, after.OK)
	r.Log = t.DecisionLog.Entries()

	allows := countAllows(r.Log, testsupport.TenantA, testsupport.EdgeDoc)
	r.note("tenantA edge ALLOW entries=%d (want 1, the in-flight only)", allows)
	r.OK = inflight.OK && !after.OK && allows == 1
	return r
}

// scenarioLeaseExpiry: drain lease runs out before the slow response arrives.
func scenarioLeaseExpiry(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeDrain, 80*time.Millisecond, 0)
	t.Origin.SetDelay(400 * time.Millisecond)
	defer t.Close()
	r := &Report{}

	inflightCh := make(chan client.Outcome, 1)
	go func() {
		inflightCh <- t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 1))
	}()
	waitForArrival(t, preopenKey(testsupport.TenantA, testsupport.EdgeDoc), 1)
	if _, err := t.Publish(ctx, testsupport.SnapshotRevokeA()); err != nil {
		r.note("publish error: %v", err)
		return r
	}
	r.note("revocation observed; lease 80ms vs origin delay 400ms")

	inflight := <-inflightCh
	r.note("in-flight after lease expiry ok=%v err=%s (want FAIL)",
		inflight.OK, inflight.Error)
	m := t.Sidecar.Metrics()
	r.note("lease/inflight counters: leaseExpired=%d inflightAborted=%d",
		m.LeaseExpired, m.InflightAborted)
	r.Log = t.DecisionLog.Entries()
	// The stream was authorized before revocation, so one ALLOW is expected at
	// the proxy even though the client never receives a response.
	allows := countAllows(r.Log, testsupport.TenantA, testsupport.EdgeDoc)
	r.note("tenantA edge ALLOW entries=%d (stream was authorized, then aborted)", allows)
	r.OK = !inflight.OK && allows == 1
	return r
}

// scenarioBarrierRace: deterministic revocation vs multiplexed new-stream race.
// Both requests park before opening; revocation is applied first; the opens are
// then released and must be rejected before any mux stream is created.
func scenarioBarrierRace(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeAbort, 0, 0)
	defer t.Close()
	r := &Report{}

	ch1 := startParkedSync(ctx, t, doc(testsupport.TenantA, testsupport.EdgeDoc, 1))
	ch2 := startParkedSync(ctx, t, doc(testsupport.TenantA, testsupport.EdgeDoc, 2))
	waitForParked(t, 2)
	r.note("two requests parked at the sidecar pre-open barrier")

	if _, err := t.Publish(ctx, testsupport.SnapshotRevokeA()); err != nil {
		r.note("publish error: %v", err)
		return r
	}
	waitForArrival(t, revokedKey(testsupport.TenantA, testsupport.EdgeDoc), 1)
	r.note("revocation boundary observed BEFORE releasing the stream opens")

	t.Barrier.Open(gateGo)
	o1 := <-ch1
	o2 := <-ch2
	r.note("racer1 ok=%v racer2 ok=%v (both must be false)", o1.OK, o2.OK)

	entries := t.DecisionLog.Entries()
	hit := 0
	for _, e := range entries {
		if e.Tenant == testsupport.TenantA && e.Original == testsupport.EdgeDoc {
			hit++
		}
	}
	r.note("server entries for tenantA/edge=%d (want 0: no stream escaped)", hit)
	r.Log = entries
	r.Mismatch = testsupport.AssertNoAllowFor(t.DecisionLog, testsupport.TenantA, testsupport.EdgeDoc)
	r.OK = !o1.OK && !o2.OK && hit == 0 && len(r.Mismatch) == 0
	return r
}

// scenarioRollback: rollback re-allows in policy but the tombstone keeps denying.
func scenarioRollback(ctx context.Context) *Report {
	t := mustEnv(ctx, sidecar.RevokeAbort, 0, 0)
	defer t.Close()
	r := &Report{}

	baseline := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 0))
	r.note("baseline before revoke ok=%v (want true)", baseline.OK)
	_, _ = t.Publish(ctx, testsupport.SnapshotRevokeA())
	revoked := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 1))
	r.note("after revoke: ok=%v (want false)", revoked.OK)

	b, err := t.Rollback(ctx, 1)
	if err != nil {
		r.note("rollback error: %v", err)
		return r
	}
	rule, ok := b.Snapshot.Lookup(testsupport.TenantA, testsupport.EdgeDoc)
	r.note("rolled back to gen=%d; rule Allowed=%v but tombstones=%d",
		b.Snapshot.Generation, ok && rule.Allowed, len(b.Tombstones))

	afterRollback := t.Sync.SyncOne(ctx, doc(testsupport.TenantA, testsupport.EdgeDoc, 2))
	r.note("request after rollback ok=%v (must stay false)", afterRollback.OK)
	r.Log = t.DecisionLog.Entries()

	allows := countAllows(r.Log, testsupport.TenantA, testsupport.EdgeDoc)
	r.note("tenantA edge ALLOW entries=%d (want 1, baseline only)", allows)
	r.OK = baseline.OK && !revoked.OK && !afterRollback.OK && allows == 1
	return r
}

func startParkedSync(ctx context.Context, t *testsupport.Topology, d client.Document) chan client.Outcome {
	ch := make(chan client.Outcome, 1)
	go func() {
		t.Barrier.Arrive("parked")
		t.Barrier.WaitFor(gateGo)
		ch <- t.Sync.SyncOne(ctx, d)
	}()
	return ch
}

func waitForParked(t *testsupport.Topology, n int) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// The parked goroutines are released by gateGo; before release they are
		// counted via a dedicated arrival gate they touch while parking.
		if t.Barrier.ArrivalCount("parked") >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
}
