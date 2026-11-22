package pool

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"egressz/authz"
	"egressz/mux"
)

func TestPoolBorrowAndIsolation(t *testing.T) {
	var dialCount atomic.Int64
	factory := func(id authz.Identity) (*mux.Session, error) {
		dialCount.Add(1)
		sess, err := mux.Dial(loopbackClient(t), "conn-"+id.Tenant)
		if err != nil {
			return nil, err
		}
		return sess, nil
	}
	p := New(factory, 4)

	idA := authz.Identity{Tenant: "A", OriginalName: "doc", Target: "127.0.0.1:8",
		ResolutionSource: "s", PolicyGeneration: 1, ConnID: "ignored"}
	idB := idA
	idB.Tenant = "B"

	s1, borrowed, err := p.Get(idA)
	if err != nil || borrowed {
		t.Fatalf("first get must establish: %v borrowed=%v", err, borrowed)
	}
	p.Put(s1)
	s2, borrowed, err := p.Get(idA)
	if err != nil || !borrowed || s2.ConnID != s1.ConnID {
		t.Fatalf("same identity must borrow the same session: borrowed=%v", borrowed)
	}
	p.Put(s2)

	sb, borrowed, err := p.Get(idB)
	if err != nil || borrowed {
		t.Fatalf("different identity must not borrow A's session: %v borrowed=%v", err, borrowed)
	}
	if sb.ConnID == s1.ConnID {
		t.Fatal("cross-identity trust context leak: same ConnID")
	}
	p.Put(sb)

	if dialCount.Load() != 2 {
		t.Fatalf("want exactly 2 establishes, got %d", dialCount.Load())
	}
	if p.Stats().Buckets < 2 {
		t.Fatalf("want >=2 identity buckets, got %d", p.Stats().Buckets)
	}
}

func TestPoolExhaustion(t *testing.T) {
	factory := func(id authz.Identity) (*mux.Session, error) {
		return mux.Dial(loopbackClient(t), "c")
	}
	p := New(factory, 1)
	id := authz.Identity{Tenant: "A", Target: "x"}
	s1, _, err := p.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Get(id); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("want ErrPoolExhausted, got %v", err)
	}
	_ = s1.Mux.Close()
}

func TestConcurrentGetShardSafety(t *testing.T) {
	factory := func(id authz.Identity) (*mux.Session, error) {
		return mux.Dial(loopbackClient(t), "c")
	}
	p := New(factory, 32)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := authz.Identity{Tenant: "t", OriginalName: "d", Target: "x",
				PolicyGeneration: int64(i % 3)}
			s, _, err := p.Get(id)
			if err == nil {
				p.Put(s)
			}
		}(i)
	}
	wg.Wait()
}
