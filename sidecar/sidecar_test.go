package sidecar_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"example.com/authsidecar/client"
	"example.com/authsidecar/internal/testsvc"
	"example.com/authsidecar/sidecar"
)

func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v: %s", d, msg)
}

type stack struct {
	srv      *testsvc.Server
	engine   *sidecar.Engine
	resolver *sidecar.Resolver
	pool     *sidecar.Pool
	sc       *sidecar.Sidecar
}

// newStack 组装一套仅回环的 侧车+源站 测试环境。
func newStack(t *testing.T, allow map[string]map[string]bool, lease sidecar.LeaseConfig,
	handler func(map[string]string) string) *stack {
	t.Helper()
	if handler == nil {
		handler = func(h map[string]string) string { return "OK body:" + h["name"] }
	}
	srv, err := testsvc.NewServer("origin", handler)
	if err != nil {
		t.Fatal(err)
	}
	engine := sidecar.NewEngine(1, allow)
	st := &stack{srv: srv, engine: engine}
	st.resolver = &sidecar.Resolver{
		Engine:      engine,
		Backend:     sidecar.BackendFunc(func(name string) (string, error) { return srv.Addr(), nil }),
		Source:      "simdns",
		MaxAttempts: 1,
	}
	st.pool = sidecar.NewPool(func(ctx context.Context, id sidecar.Identity) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", id.Addr)
	})
	st.sc = sidecar.NewSidecar(sidecar.Config{
		Engine: engine, Resolver: st.resolver, Pool: st.pool, Lease: lease,
	})
	t.Cleanup(func() { st.sc.Close(); srv.Close() })
	return st
}

func allowAll() map[string]map[string]bool {
	return map[string]map[string]bool{
		"A": {"doc1": true, "doc2": true, "shared": true},
		"B": {"doc1": true, "doc2": true, "shared": true},
	}
}

// 撤销边界(abort 租约): 在途请求被中止; 观察撤销后新请求不得发出。
func TestRevocationBoundaryAbort(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	gate := make(chan struct{})
	st.srv.OnRequest = func(h map[string]string) { <-gate }

	errCh := make(chan error, 1)
	go func() {
		_, err := st.sc.Fetch(context.Background(), "A", "doc1", "/doc1")
		errCh <- err
	}()
	waitFor(t, 3*time.Second, func() bool { return len(st.srv.Received()) == 1 }, "request in flight")

	st.engine.Revoke("A", "*")
	select {
	case err := <-errCh:
		if !errors.Is(err, sidecar.ErrInflightRevoked) {
			t.Fatalf("want ErrInflightRevoked, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request not aborted after revocation")
	}
	close(gate)

	// 观察撤销后禁止发出新请求。
	if _, err := st.sc.Fetch(context.Background(), "A", "doc1", "/doc1"); !errors.Is(err, sidecar.ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
	if n := len(st.srv.Received()); n != 1 {
		t.Fatalf("server must not see post-revocation requests, got %d", n)
	}
}

// 撤销边界(drain 租约): 租约内完成则成功; 超时则中止。
func TestRevocationBoundaryDrain(t *testing.T) {
	t.Run("completes within lease", func(t *testing.T) {
		st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseDrain, DrainTimeout: 400 * time.Millisecond}, nil)
		gate := make(chan struct{})
		st.srv.OnRequest = func(h map[string]string) { <-gate }

		type res struct {
			body string
			err  error
		}
		resCh := make(chan res, 1)
		go func() {
			b, err := st.sc.Fetch(context.Background(), "A", "doc1", "/doc1")
			resCh <- res{b, err}
		}()
		waitFor(t, 3*time.Second, func() bool { return len(st.srv.Received()) == 1 }, "request in flight")
		st.engine.Revoke("A", "*")
		time.Sleep(50 * time.Millisecond) // 在排空租约内放行响应
		close(gate)
		select {
		case r := <-resCh:
			if r.err != nil {
				t.Fatalf("drain lease should let in-flight request complete, got %v", r.err)
			}
			if r.body != "body:doc1" {
				t.Fatalf("unexpected body %q", r.body)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("fetch stuck")
		}
	})

	t.Run("aborted after lease expiry", func(t *testing.T) {
		st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseDrain, DrainTimeout: 150 * time.Millisecond}, nil)
		gate := make(chan struct{})
		st.srv.OnRequest = func(h map[string]string) { <-gate }

		errCh := make(chan error, 1)
		go func() {
			_, err := st.sc.Fetch(context.Background(), "A", "doc1", "/doc1")
			errCh <- err
		}()
		waitFor(t, 3*time.Second, func() bool { return len(st.srv.Received()) == 1 }, "request in flight")
		st.engine.Revoke("A", "*")
		select {
		case err := <-errCh:
			if !errors.Is(err, sidecar.ErrInflightRevoked) {
				t.Fatalf("want ErrInflightRevoked after lease expiry, got %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("in-flight request not aborted after drain lease expired")
		}
		close(gate)
	})
}

// 系统故障 fail-closed: 引擎故障时返回错误, 不拨号、不退回直连。
func TestEngineFailureFailsClosed(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	st.engine.SetFailed(true)
	if _, err := st.sc.Fetch(context.Background(), "A", "doc1", "/doc1"); !errors.Is(err, sidecar.ErrEngineFailure) {
		t.Fatalf("want ErrEngineFailure, got %v", err)
	}
	if n := st.pool.ConnCount(); n != 0 {
		t.Fatalf("no connection may be established on engine failure, got %d", n)
	}
	if n := len(st.srv.Received()); n != 0 {
		t.Fatalf("server must see nothing on engine failure, got %d", n)
	}
}

// 身份隔离: 同一目标地址、不同租户 -> 不同连接; 撤销 A 不影响 B。
func TestIdentityIsolation(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	ctx := context.Background()
	if _, err := st.sc.Fetch(ctx, "A", "shared", "/shared"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.sc.Fetch(ctx, "B", "shared", "/shared"); err != nil {
		t.Fatal(err)
	}
	if n := st.pool.ConnCount(); n != 2 {
		t.Fatalf("same addr but different identities must not share a connection, got %d conns", n)
	}
	recv := st.srv.Received()
	if len(recv) != 2 || recv[0].Headers["idkey"] == recv[1].Headers["idkey"] {
		t.Fatalf("requests must carry distinct identity keys: %+v", recv)
	}

	st.engine.Revoke("A", "*")
	if _, err := st.sc.Fetch(ctx, "A", "shared", "/shared"); !errors.Is(err, sidecar.ErrRevoked) {
		t.Fatalf("A must be revoked, got %v", err)
	}
	if _, err := st.sc.Fetch(ctx, "B", "shared", "/shared"); err != nil {
		t.Fatalf("B must be unaffected by A's revocation, got %v", err)
	}
}

// 迟到解析丢弃: 解析期间发生撤销, 结果必须丢弃, 不得用于发送。
func TestLateResolutionDiscarded(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	st.resolver.Latency = 150 * time.Millisecond

	errCh := make(chan error, 1)
	go func() {
		_, err := st.sc.Fetch(context.Background(), "A", "doc1", "/doc1")
		errCh <- err
	}()
	time.Sleep(30 * time.Millisecond) // 解析进行中
	st.engine.Revoke("A", "doc1")
	select {
	case err := <-errCh:
		if !errors.Is(err, sidecar.ErrStaleResolution) && !errors.Is(err, sidecar.ErrRevoked) {
			t.Fatalf("want stale/revoked error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fetch did not observe revocation during resolution")
	}
	if n := len(st.srv.Received()); n != 0 {
		t.Fatalf("stale resolution must not be used, server saw %d requests", n)
	}
}

// 有界重试: 后端持续失败时在 MaxAttempts 次后放弃; 偶发失败可恢复。
func TestBoundedRetry(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)

	var attempts int32
	st.resolver.MaxAttempts = 3
	st.resolver.Backoff = time.Millisecond
	st.resolver.Backend = sidecar.BackendFunc(func(name string) (string, error) {
		atomic.AddInt32(&attempts, 1)
		return "", fmt.Errorf("simulated dns failure")
	})
	if _, err := st.sc.Fetch(context.Background(), "A", "doc1", "/doc1"); err == nil {
		t.Fatal("expected resolution failure")
	}
	if n := atomic.LoadInt32(&attempts); n != 3 {
		t.Fatalf("bounded retry must stop at MaxAttempts=3, got %d", n)
	}

	atomic.StoreInt32(&attempts, 0)
	st.resolver.Backend = sidecar.BackendFunc(func(name string) (string, error) {
		if atomic.AddInt32(&attempts, 1) < 2 {
			return "", fmt.Errorf("transient failure")
		}
		return st.srv.Addr(), nil
	})
	if _, err := st.sc.Fetch(context.Background(), "A", "doc1", "/doc1"); err != nil {
		t.Fatalf("transient failure should be retried, got %v", err)
	}
	if n := atomic.LoadInt32(&attempts); n != 2 {
		t.Fatalf("expected 2 attempts, got %d", n)
	}
}

// 重定向: 每一跳都重新授权并进入身份; 目标未授权则第二跳被拒绝。
func TestRedirectReauthorization(t *testing.T) {
	handler := func(h map[string]string) string {
		if h["name"] == "doc1" {
			return "REDIRECT doc2"
		}
		return "OK body:" + h["name"]
	}
	allow := map[string]map[string]bool{"A": {"doc1": true}}
	st := newStack(t, allow, sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, handler)
	ctx := context.Background()

	if _, err := st.sc.Fetch(ctx, "A", "doc1", "/doc1"); !errors.Is(err, sidecar.ErrNotAllowed) {
		t.Fatalf("redirect target not allowed: want ErrNotAllowed, got %v", err)
	}
	if n := len(st.srv.Received()); n != 1 {
		t.Fatalf("only the first hop may reach the server, got %d", n)
	}

	// 放行 doc2 后: 两跳都到达, 第二跳身份包含重定向链, 且新建连接。
	allow["A"]["doc2"] = true
	st.engine.SetPolicy(2, allow)
	body, err := st.sc.Fetch(ctx, "A", "doc1", "/doc1")
	if err != nil {
		t.Fatal(err)
	}
	if body != "body:doc2" {
		t.Fatalf("unexpected body %q", body)
	}
	recv := st.srv.Received()
	if len(recv) != 3 {
		t.Fatalf("expected 3 received requests total, got %d", len(recv))
	}
	second := recv[2].Headers
	if second["hops"] != "doc1>doc2" || second["hop"] != "1" {
		t.Fatalf("second hop identity must carry redirect chain, got %+v", second)
	}
	// 策略世代计入身份: doc1@gen1(首次失败)、doc1@gen2、doc2@gen2 各一条连接。
	if n := st.pool.ConnCount(); n != 3 {
		t.Fatalf("each (identity, policy gen, redirect hop) is a distinct connection, got %d conns", n)
	}
}

// 策略回滚不恢复已撤销权限。
func TestPolicyRollbackDoesNotRestoreRevocation(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	ctx := context.Background()

	st.engine.Revoke("A", "doc1")
	// 回滚到旧世代(其中 doc1 原本允许)。
	st.engine.SetPolicy(0, allowAll())
	if _, err := st.sc.Fetch(ctx, "A", "doc1", "/doc1"); !errors.Is(err, sidecar.ErrRevoked) {
		t.Fatalf("rollback must not restore revoked permission, got %v", err)
	}
	// 前滚到新世代也不行。
	st.engine.SetPolicy(9, allowAll())
	if _, err := st.sc.Fetch(ctx, "A", "doc1", "/doc1"); !errors.Is(err, sidecar.ErrRevoked) {
		t.Fatalf("roll-forward must not restore revoked permission, got %v", err)
	}
	// 其他租户/名称不受影响。
	if _, err := st.sc.Fetch(ctx, "B", "doc1", "/doc1"); err != nil {
		t.Fatalf("B must be unaffected, got %v", err)
	}
	if _, err := st.sc.Fetch(ctx, "A", "doc2", "/doc2"); err != nil {
		t.Fatalf("unrelated name must be unaffected, got %v", err)
	}
}

// 多路复用: 同一身份的两次请求复用同一条连接的不同流。
func TestMuxStreamReuse(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := st.sc.Fetch(ctx, "A", "doc1", "/doc1"); err != nil {
			t.Fatal(err)
		}
	}
	if n := st.pool.ConnCount(); n != 1 {
		t.Fatalf("same identity must reuse one connection, got %d", n)
	}
	recv := st.srv.Received()
	if len(recv) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(recv))
	}
	if recv[0].ConnID != recv[1].ConnID || recv[0].Stream == recv[1].Stream {
		t.Fatalf("requests must share the connection but use distinct streams: %+v", recv)
	}
}

// 确定性屏障: 撤销与"在已有多路复用会话上打开新流"竞争。
// 钩子把新流打开卡在最终授权复核之前, 撤销先行, 复核必须拒绝。
func TestRevokeVsMuxStreamOpenRace(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	ctx := context.Background()
	if _, err := st.sc.Fetch(ctx, "A", "doc1", "/doc1"); err != nil {
		t.Fatal(err) // 建立并入池连接
	}
	if n := st.pool.ConnCount(); n != 1 {
		t.Fatalf("expected pooled connection, got %d", n)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	st.sc.SetHooks(sidecar.Hooks{
		BeforeStreamOpen: func(id sidecar.Identity) {
			close(entered)
			<-release
		},
	})
	errCh := make(chan error, 1)
	go func() {
		_, err := st.sc.Fetch(ctx, "A", "doc1", "/doc1") // 复用会话, 开新流
		errCh <- err
	}()
	<-entered // 新流即将在已有多路复用会话上打开
	st.engine.Revoke("A", "doc1")
	close(release)

	select {
	case err := <-errCh:
		if !errors.Is(err, sidecar.ErrRevoked) {
			t.Fatalf("want ErrRevoked, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fetch stuck")
	}
	if n := len(st.srv.Received()); n != 1 {
		t.Fatalf("no new stream may be sent after revocation, server saw %d requests", n)
	}
}

// 文档同步客户端: 失败即中止, 无静默部分成功。
func TestDocSyncClient(t *testing.T) {
	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	ctx := context.Background()
	c := &client.DocSync{Sidecar: st.sc, Tenant: "A"}

	docs, err := c.Sync(ctx, []string{"doc1", "doc2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 docs, got %d", len(docs))
	}

	st.engine.Revoke("A", "doc2")
	if _, err := c.Sync(ctx, []string{"doc1", "doc2"}); !errors.Is(err, sidecar.ErrRevoked) {
		t.Fatalf("sync must fail closed on revocation, got %v", err)
	}
}

// 经代理的实际连接计入身份: 代理与源站都留有接收记录。
func TestProxyPath(t *testing.T) {
	proxy, err := testsvc.NewProxy()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Close)

	st := newStack(t, allowAll(), sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, nil)
	// 重新组装经代理的侧车。
	st.sc.Close()
	pool := sidecar.NewPool(func(ctx context.Context, id sidecar.Identity) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", proxy.Addr()) // 实际连接指向代理
	})
	sc := sidecar.NewSidecar(sidecar.Config{
		Engine: st.engine, Resolver: st.resolver, Pool: pool,
		Lease: sidecar.LeaseConfig{Mode: sidecar.LeaseAbort}, ViaProxy: true,
	})
	t.Cleanup(sc.Close)

	if _, err := sc.Fetch(context.Background(), "A", "doc1", "/doc1"); err != nil {
		t.Fatal(err)
	}
	if n := len(proxy.Received()); n != 1 {
		t.Fatalf("proxy must see the request, got %d", n)
	}
	if got := proxy.Received()[0].Headers["via"]; got != "proxy" {
		t.Fatalf("identity must record the actual connection path, via=%q", got)
	}
	if n := len(st.srv.Received()); n != 1 {
		t.Fatalf("origin must see the forwarded request, got %d", n)
	}
}
