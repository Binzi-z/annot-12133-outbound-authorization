package client_test

import (
	"context"
	"testing"

	"egressz/client"
	"egressz/sidecar"
	"egressz/testsupport"
)

func TestSyncClientIdempotentPuts(t *testing.T) {
	ctx := context.Background()
	top, err := testsupport.Standup(ctx, testsupport.Config{
		RevokeMode: sidecar.RevokeAbort, Initial: testsupport.InitialSnapshot(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer top.Close()

	doc := client.Document{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc, Body: "v1", Rev: 7}
	o1 := top.Sync.SyncOne(ctx, doc)
	o2 := top.Sync.SyncOne(ctx, doc)
	if !o1.OK || !o2.OK {
		t.Fatalf("both syncs must succeed: %+v %+v", o1, o2)
	}
	stored := top.Origin.Docs()
	key := testsupport.TenantA + "/" + testsupport.EdgeDoc
	got, ok := stored[key]
	if !ok {
		t.Fatal("origin never stored the document")
	}
	// Two physical PUTs arrive (distinct nonces); versioning is monotonic.
	if got.Version != 2 {
		t.Fatalf("want origin version 2 after two puts, got %d", got.Version)
	}
	if len(top.Origin.Received()) != 2 {
		t.Fatalf("want 2 origin request bodies, got %d", len(top.Origin.Received()))
	}

	// Concurrent interleaving of two tenants completes without cross-talk.
	outcomes := top.Sync.SyncMany(ctx, []client.Document{
		{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc, Body: "a", Rev: 1},
		{Tenant: testsupport.TenantB, Name: testsupport.EdgeDoc, Body: "b", Rev: 1},
		{Tenant: testsupport.TenantA, Name: testsupport.EdgeDoc, Body: "a2", Rev: 2},
		{Tenant: testsupport.TenantB, Name: testsupport.EdgeDoc, Body: "b2", Rev: 2},
	}, 4)
	for _, o := range outcomes {
		if !o.OK {
			t.Fatalf("interleaved sync failed: %+v", o)
		}
	}
}
