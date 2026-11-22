package model_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"example.com/authsidecar/client"
	"example.com/authsidecar/internal/testsvc"
	"example.com/authsidecar/model"
	"example.com/authsidecar/sidecar"
)

// 场景: 租户 A 同步 doc1, 第一跳被重定向到 doc2; 租户 B 同步 bdoc。
// A 链: Connect#1 -> Borrow#1 -> Response#1 -> Redirect -> Connect#2 -> Borrow#2 -> Response#2
// B 链: Connect#1 -> Borrow#1 -> Response#1
// Revoke(A) 可落在任意位置。共 11!/(7!·3!) = 1320 种交错。
func scenarioEvents() ([]model.Event, [][2]int) {
	events := []model.Event{
		{ID: 0, Kind: model.Connect, Tenant: "A", Occ: 1},
		{ID: 1, Kind: model.Borrow, Tenant: "A", Occ: 1},
		{ID: 2, Kind: model.Response, Tenant: "A", Occ: 1},
		{ID: 3, Kind: model.Connect, Tenant: "A", Occ: 2},
		{ID: 4, Kind: model.Borrow, Tenant: "A", Occ: 2},
		{ID: 5, Kind: model.Response, Tenant: "A", Occ: 2},
		{ID: 6, Kind: model.Connect, Tenant: "B", Occ: 1},
		{ID: 7, Kind: model.Borrow, Tenant: "B", Occ: 1},
		{ID: 8, Kind: model.Response, Tenant: "B", Occ: 1},
		{ID: 9, Kind: model.Revoke, Tenant: "A"},
		{ID: 10, Kind: model.Redirect, Tenant: "A", Occ: 1},
	}
	edges := [][2]int{
		{0, 1}, {1, 2}, {2, 10}, {10, 3}, {3, 4}, {4, 5}, // A 链(含重定向)
		{6, 7}, {7, 8}, // B 链
	}
	return events, edges
}

// runEnv 是屏障驱动执行器: 每个事件一对 (gate, reached)。
// 系统钩子先等 gate 再报 reached; 调度器按轨迹顺序开 gate、等 reached,
// 从而把真实并发系统确定性地驱动到指定交错。
type runEnv struct {
	byKey   map[string]int // tenant|kind|occ -> 事件 ID
	gates   map[int]chan struct{}
	reached map[int]chan struct{}

	occMu sync.Mutex
	occ   map[string]int

	pendingMu      sync.Mutex
	pendingConnect map[string]int
	pendingBorrow  map[string]int

	authMu sync.Mutex
	auth   map[int]bool // Borrow 事件 ID -> 侧车实际授权结果
}

func newRunEnv(events []model.Event) *runEnv {
	r := &runEnv{
		byKey:          map[string]int{},
		gates:          map[int]chan struct{}{},
		reached:        map[int]chan struct{}{},
		occ:            map[string]int{},
		pendingConnect: map[string]int{},
		pendingBorrow:  map[string]int{},
		auth:           map[int]bool{},
	}
	for _, e := range events {
		r.byKey[fmt.Sprintf("%s|%d|%d", e.Tenant, e.Kind, e.Occ)] = e.ID
		r.gates[e.ID] = make(chan struct{})
		r.reached[e.ID] = make(chan struct{})
	}
	return r
}

func (r *runEnv) nextEvent(tenant string, kind model.Kind) (int, bool) {
	r.occMu.Lock()
	defer r.occMu.Unlock()
	k := fmt.Sprintf("%s|%d", tenant, kind)
	r.occ[k]++
	id, ok := r.byKey[fmt.Sprintf("%s|%d", k, r.occ[k])]
	return id, ok
}

func (r *runEnv) beforeConnect(tenant string) {
	id, ok := r.nextEvent(tenant, model.Connect)
	if !ok {
		return
	}
	<-r.gates[id]
	r.pendingMu.Lock()
	r.pendingConnect[tenant] = id
	r.pendingMu.Unlock()
}

func (r *runEnv) afterConnect(tenant string) {
	r.pendingMu.Lock()
	id, ok := r.pendingConnect[tenant]
	r.pendingMu.Unlock()
	if ok {
		close(r.reached[id])
	}
}

func (r *runEnv) beforeBorrow(tenant string) {
	id, ok := r.nextEvent(tenant, model.Borrow)
	if !ok {
		return
	}
	<-r.gates[id]
	r.pendingMu.Lock()
	r.pendingBorrow[tenant] = id
	r.pendingMu.Unlock()
}

func (r *runEnv) afterBorrow(tenant string, authorized bool) {
	r.pendingMu.Lock()
	id, ok := r.pendingBorrow[tenant]
	r.pendingMu.Unlock()
	if !ok {
		return
	}
	r.authMu.Lock()
	r.auth[id] = authorized
	r.authMu.Unlock()
	close(r.reached[id])
}

func (r *runEnv) onResponse(tenant string) {
	id, ok := r.nextEvent(tenant, model.Response)
	if !ok {
		return
	}
	<-r.gates[id]
	close(r.reached[id])
}

// runTrace 在真实侧车 + 回环服务上按 trace 的交错重放, 并比对:
//  1. 侧车对每个 Borrow 的实际授权判定 == oracle 判定
//  2. 服务端实际接收日志 == oracle 判定为授权的借用集合(不多不少)
func runTrace(t *testing.T, trace []model.Event) {
	t.Helper()
	oracle := model.Replay(trace)
	events, _ := scenarioEvents()
	r := newRunEnv(events)

	srv, err := testsvc.NewServer("origin", func(h map[string]string) string {
		if h["name"] == "doc1" {
			return "REDIRECT doc2"
		}
		return "OK body:" + h["name"]
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.OnRequest = func(h map[string]string) { r.onResponse(h["tenant"]) }

	engine := sidecar.NewEngine(1, map[string]map[string]bool{
		"A": {"doc1": true, "doc2": true},
		"B": {"bdoc": true},
	})
	resolver := &sidecar.Resolver{
		Engine: engine,
		Backend: sidecar.BackendFunc(func(name string) (string, error) {
			return srv.Addr(), nil
		}),
		Source:      "simdns",
		MaxAttempts: 1,
	}
	pool := sidecar.NewPool(func(ctx context.Context, id sidecar.Identity) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", id.Addr)
	})
	pool.BeforeDial = func(id sidecar.Identity) { r.beforeConnect(id.Tenant) }
	pool.AfterDial = func(id sidecar.Identity) { r.afterConnect(id.Tenant) }

	sc := sidecar.NewSidecar(sidecar.Config{
		Engine:   engine,
		Resolver: resolver,
		Pool:     pool,
		Lease:    sidecar.LeaseConfig{Mode: sidecar.LeaseAbort},
		Hooks: sidecar.Hooks{
			BeforeStreamOpen: func(id sidecar.Identity) { r.beforeBorrow(id.Tenant) },
			AfterAuthorize:   func(id sidecar.Identity, ok bool) { r.afterBorrow(id.Tenant, ok) },
		},
	})
	defer sc.Close()

	done := map[string]chan struct{}{"A": make(chan struct{}), "B": make(chan struct{})}
	go func() {
		defer close(done["A"])
		c := &client.DocSync{Sidecar: sc, Tenant: "A"}
		_, _ = c.Sync(context.Background(), []string{"doc1"})
	}()
	go func() {
		defer close(done["B"])
		c := &client.DocSync{Sidecar: sc, Tenant: "B"}
		_, _ = c.Sync(context.Background(), []string{"bdoc"})
	}()

	// 调度器: 按轨迹顺序驱动。Revoke 是动作事件; Redirect 是客户端标记事件。
	skipped := map[string]bool{}
	for i, ev := range trace {
		switch ev.Kind {
		case model.Revoke:
			engine.Revoke(ev.Tenant, "*")
			continue
		case model.Redirect:
			continue
		}
		if skipped[ev.Tenant] {
			if oracle.Reachable(trace, i) {
				t.Fatalf("trace %v: event %+v skipped but reachable", trace, ev)
			}
			continue
		}
		close(r.gates[ev.ID])
		select {
		case <-r.reached[ev.ID]:
		case <-done[ev.Tenant]:
			// 租户已因 fail-closed 终止, 该事件及后续事件不可达。
			if oracle.Reachable(trace, i) {
				t.Fatalf("trace %v: reachable event %+v never occurred", trace, ev)
			}
			skipped[ev.Tenant] = true
		case <-time.After(15 * time.Second):
			t.Fatalf("trace %v: harness stuck at %+v", trace, ev)
		}
	}

	for tenant, ch := range done {
		select {
		case <-ch:
		case <-time.After(15 * time.Second):
			t.Fatalf("trace %v: tenant %s did not finish", trace, tenant)
		}
	}

	// 比对: 服务端实际接收日志 vs oracle 授权判定。
	type reqKey struct{ tenant, hop string }
	unexpected := map[reqKey]bool{}
	for _, rr := range srv.Received() {
		k := reqKey{rr.Headers["tenant"], rr.Headers["hop"]}
		if unexpected[k] {
			t.Fatalf("trace %v: duplicate request at server: %v", trace, k)
		}
		unexpected[k] = true
	}
	for _, ev := range trace {
		if ev.Kind != model.Borrow {
			continue
		}
		hop := "0"
		if ev.Occ == 2 {
			hop = "1"
		}
		k := reqKey{ev.Tenant, hop}
		if oracle.Authorized(ev.ID) {
			if !unexpected[k] {
				t.Fatalf("trace %v: authorized borrow %+v missing from server log", trace, ev)
			}
			if a, ok := r.auth[ev.ID]; !ok || !a {
				t.Fatalf("trace %v: borrow %+v authorized by oracle but denied by sidecar", trace, ev)
			}
			delete(unexpected, k)
		} else if a, ok := r.auth[ev.ID]; ok && a {
			t.Fatalf("trace %v: borrow %+v denied by oracle but authorized by sidecar", trace, ev)
		}
	}
	for k := range unexpected {
		t.Fatalf("trace %v: unauthorized request reached server: %v", trace, k)
	}
}

func TestTwoTenantInterleavings(t *testing.T) {
	events, edges := scenarioEvents()
	traces := model.Enumerate(events, edges)
	if len(traces) != 1320 {
		t.Fatalf("expected 1320 interleavings, got %d", len(traces))
	}
	for idx, trace := range traces {
		if testing.Short() && idx%11 != 0 {
			continue
		}
		runTrace(t, trace)
		if t.Failed() {
			t.Fatalf("failed on trace %d: %v", idx, trace)
		}
	}
}
