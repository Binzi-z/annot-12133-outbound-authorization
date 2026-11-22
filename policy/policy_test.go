package policy

import "testing"

func TestEvaluateFailClosedOnEmptyBundle(t *testing.T) {
	res := Evaluate(Bundle{}, testIdentity("t1", "doc"))
	if res.Decision != Deny || res.Reason != "no_policy_loaded" {
		t.Fatalf("expected fail-closed deny, got %+v", res)
	}
}

func TestTombstoneBeatsRollback(t *testing.T) {
	gen1 := Snapshot{Generation: 1, Rules: []Rule{
		{Tenant: "t1", OriginalName: "doc", Allowed: true, MaxRedirects: -1},
	}}
	gen2 := Snapshot{Generation: 2, Rules: nil} // rule removed => tombstone

	svc := NewService(gen1)
	if err := svc.Publish(gen2); err != nil {
		t.Fatal(err)
	}
	if len(svc.Tombstones()) != 1 {
		t.Fatalf("want 1 tombstone, got %d", len(svc.Tombstones()))
	}

	// Rollback re-publishes gen1 rules under a new generation.
	rb, err := svc.Rollback(1)
	if err != nil {
		t.Fatal(err)
	}
	if rb.Generation != 3 {
		t.Fatalf("rollback must mint a new generation, got %d", rb.Generation)
	}
	b := svc.Bundle()
	rule, ok := b.Snapshot.Lookup("t1", "doc")
	if !ok || !rule.Allowed {
		t.Fatal("rollback should restore an allowing rule")
	}
	res := Evaluate(b, testIdentity("t1", "doc"))
	if res.Decision != Deny || !ReasonIsRevocation(res.Reason) {
		t.Fatalf("tombstone must keep denying after rollback, got %+v", res)
	}
}

func TestDiffRevoked(t *testing.T) {
	old := Snapshot{Generation: 1, Rules: []Rule{
		{Tenant: "t1", OriginalName: "a", Allowed: true},
		{Tenant: "t1", OriginalName: "b", Allowed: true},
	}}
	new := Snapshot{Generation: 2, Rules: []Rule{
		{Tenant: "t1", OriginalName: "a", Allowed: true},
		{Tenant: "t1", OriginalName: "b", Allowed: false},
	}}
	got := DiffRevoked(old, new)
	if len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("want single revocation of b, got %+v", got)
	}
}

func TestRedirectRules(t *testing.T) {
	r := Rule{Allowed: true, MaxRedirects: 1, DenyTargets: []string{"127.0.0.1:9"}}
	if ok, _ := r.Permits(1, []string{"127.0.0.1:8"}); !ok {
		t.Fatal("one hop should be allowed")
	}
	if ok, reason := r.Permits(2, nil); ok || reason != "redirect_chain_too_long" {
		t.Fatalf("two hops must be denied, got %v %s", ok, reason)
	}
	if ok, reason := r.Permits(1, []string{"127.0.0.1:9"}); ok || reason == "" {
		t.Fatalf("denied target must reject, got %v %s", ok, reason)
	}
}
