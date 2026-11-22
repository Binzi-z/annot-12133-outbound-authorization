package testsupport

import "egressz/policy"

// Tenant names used across the reference model.
const (
	TenantA = "tenant-alpha"
	TenantB = "tenant-bravo"
)

// Document names.
const (
	EdgeDoc     = "edge-doc"
	RedirectDoc = "redirect-doc"
)

// InitialSnapshot is generation 1: both tenants can use the edge document;
// tenant A may also traverse one redirect hop. The ghost document is allowed
// by policy so the fail-closed dial guard (not policy) is the decision point.
func InitialSnapshot() policy.Snapshot {
	return policy.Snapshot{
		Generation: 1,
		Rules: []policy.Rule{
			{Tenant: TenantA, OriginalName: EdgeDoc, Allowed: true, MaxRedirects: 2},
			{Tenant: TenantA, OriginalName: RedirectDoc, Allowed: true, MaxRedirects: 2},
			{Tenant: TenantA, OriginalName: "ghost-doc", Allowed: true, MaxRedirects: 0},
			{Tenant: TenantB, OriginalName: EdgeDoc, Allowed: true, MaxRedirects: 0},
			{Tenant: TenantB, OriginalName: RedirectDoc, Allowed: false},
		},
	}
}

// SnapshotRevokeA removes tenant A's edge-doc permission at generation 2.
func SnapshotRevokeA() policy.Snapshot {
	return policy.Snapshot{
		Generation: 2,
		Rules: []policy.Rule{
			{Tenant: TenantA, OriginalName: RedirectDoc, Allowed: true, MaxRedirects: 2},
			{Tenant: TenantB, OriginalName: EdgeDoc, Allowed: true, MaxRedirects: 0},
			{Tenant: TenantB, OriginalName: RedirectDoc, Allowed: false},
		},
	}
}

// SnapshotRollbackLike1 re-allows tenant A at generation 3, mimicking a
// rollback to generation 1. The tombstone created at gen 2 still wins.
func SnapshotRollbackLike1() policy.Snapshot {
	return policy.Snapshot{
		Generation: 3,
		Rules: []policy.Rule{
			{Tenant: TenantA, OriginalName: EdgeDoc, Allowed: true, MaxRedirects: 2},
			{Tenant: TenantA, OriginalName: RedirectDoc, Allowed: true, MaxRedirects: 2},
			{Tenant: TenantB, OriginalName: EdgeDoc, Allowed: true, MaxRedirects: 0},
			{Tenant: TenantB, OriginalName: RedirectDoc, Allowed: false},
		},
	}
}
