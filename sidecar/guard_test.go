package sidecar

import (
	"errors"
	"testing"
)

func TestGuardedDialerOnlyAllowsLoopbackAllowlist(t *testing.T) {
	g := NewGuardedDialer("127.0.0.1:63001")

	if g.Allowed("127.0.0.1:63001") != true {
		t.Fatal("allowlisted address should be permitted")
	}
	if _, err := g.Dial("tcp", "127.0.0.1:9"); !errors.Is(err, ErrDirectDialBlocked) {
		t.Fatalf("unlisted loopback must be blocked, got %v", err)
	}
	if _, err := g.Dial("tcp", "8.8.8.8:53"); !errors.Is(err, ErrDirectDialBlocked) {
		t.Fatalf("public address must be blocked, got %v", err)
	}
	if _, err := g.Dial("udp", "127.0.0.1:63001"); !errors.Is(err, ErrDirectDialBlocked) {
		t.Fatalf("non-TCP network must be blocked, got err")
	}
}

func TestLateResolutionDiscard(t *testing.T) {
	r := NewStaticResolver("src")
	r.Set("doc", "127.0.0.1:1000")
	table := NewResolverTable(r)

	res, token, err := table.Resolve(todoContext(), "doc")
	if err != nil || res.Target != "127.0.0.1:1000" {
		t.Fatalf("fresh resolution failed: %v", err)
	}
	table.Bump()
	// Simulate an answer computed under the old token arriving after the bump.
	if table.token.Load() == token {
		t.Fatal("bump must advance the generation token")
	}
	if _, _, err := table.Resolve(todoContext(), "doc"); err != nil {
		t.Fatal("a fresh resolve after the bump must succeed")
	}
	if _, err := r.Resolve(todoContext(), "missing"); !errors.Is(err, ErrUnknownName) {
		t.Fatalf("unknown name must error, got %v", err)
	}
}
