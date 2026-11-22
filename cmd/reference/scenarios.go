package main

import "context"

// Scenario is one enumerated interleaving.
type Scenario struct {
	ID    int
	Title string
	Run   func(ctx context.Context) *Report
}

func buildScenarios() []Scenario {
	return []Scenario{
		{1, "connection establishment: two tenants, same target, distinct identities", scenarioEstablish},
		{2, "mux reuse and pool borrowing within one identity", scenarioBorrow},
		{3, "same target address, different identity cannot borrow trust", scenarioNoBorrowCrossIdentity},
		{4, "redirect hop re-authorizes with extended identity chain", scenarioRedirect},
		{5, "policy deny at the proxy is recorded and never retried", scenarioDeny},
		{6, "revocation (abort): new request blocked, in-flight killed", scenarioRevokeAbort},
		{7, "revocation (drain): in-flight completes inside lease, new blocked", scenarioRevokeDrain},
		{8, "drain lease expiry aborts a slow in-flight request", scenarioLeaseExpiry},
		{9, "deterministic barrier: revocation vs mux new-stream race", scenarioBarrierRace},
		{10, "policy rollback does not restore a revoked permission", scenarioRollback},
		{11, "bounded retry on transport failure, then success", scenarioBoundedRetry},
		{12, "late resolution answer is discarded", scenarioLateResolution},
		{13, "fail-closed: guarded dialer refuses direct/non-loopback egress", scenarioFailClosed},
		{14, "two-tenant interleaved establish/borrow/redirect/revoke/response", scenarioInterleave},
	}
}
