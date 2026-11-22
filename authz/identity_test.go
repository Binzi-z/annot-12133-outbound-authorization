package authz

import "testing"

func TestTokenConnBindingAndTamper(t *testing.T) {
	secret := []byte("k")
	id := Identity{
		Tenant: "t", PolicyGeneration: 1, OriginalName: "doc",
		ResolutionSource: "src", Target: "127.0.0.1:1", ConnID: "conn-1",
	}
	tok := MintToken(secret, id, "n1")
	got, err := VerifyToken(secret, mustJSON(tok))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if got.Fingerprint() != id.Fingerprint() {
		t.Fatal("fingerprint mismatch")
	}

	// Tamper with the identity after signing.
	tok.Identity.ConnID = "conn-2"
	if _, err := VerifyToken(secret, mustJSON(tok)); err == nil {
		t.Fatal("tampered token must fail MAC verification")
	}

	// Wrong secret.
	if _, err := VerifyToken([]byte("other"), mustJSON(MintToken(secret, id, "n2"))); err == nil {
		t.Fatal("token signed with another secret must be rejected")
	}

	// Missing ConnID is refused even with a valid MAC.
	bad := id
	bad.ConnID = ""
	raw := mustJSON(MintToken(secret, bad, "n3"))
	if _, err := VerifyToken(secret, raw); err == nil {
		t.Fatal("token without conn binding must be rejected")
	}
}

func TestPoolKeyIsolatesIdentitiesSameTarget(t *testing.T) {
	base := Identity{
		PolicyGeneration: 1, OriginalName: "doc",
		ResolutionSource: "src", Target: "127.0.0.1:8000", ConnID: "c",
	}
	a := base
	a.Tenant = "A"
	b := base
	b.Tenant = "B"
	if a.PoolKey() == b.PoolKey() {
		t.Fatal("different tenants sharing an address must have different pool keys")
	}
	// ConnID must NOT change the pool key (connections share a bucket).
	a2 := a
	a2.ConnID = "different"
	if a.PoolKey() != a2.PoolKey() {
		t.Fatal("ConnID must be excluded from the pool key")
	}
	// But fingerprint must include ConnID.
	if a.Fingerprint() == a2.Fingerprint() {
		t.Fatal("fingerprint must distinguish connections")
	}
	// A redirect hop changes both key and fingerprint.
	a3 := a
	a3.Hops = []Hop{{From: "x", To: "y", Address: "127.0.0.1:9"}}
	if a3.PoolKey() == a.PoolKey() {
		t.Fatal("different redirect chains must not share a pool bucket")
	}
}
