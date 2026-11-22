// Package sidecar 实现本地出站授权侧车。所有出站请求都必须经过授权身份
// 判定; 系统故障(策略引擎、解析、拨号)一律 fail-closed, 不存在直连回退。
package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"example.com/authsidecar/internal/protocol"
)

var (
	// ErrTooManyRedirects 表示重定向跳数超过上限。
	ErrTooManyRedirects = errors.New("sidecar: too many redirects")
	// ErrInflightRevoked 表示已发送的请求在租约内被撤销中止(或排空超时)。
	ErrInflightRevoked = errors.New("sidecar: in-flight request revoked before completion")
)

// LeaseMode 决定观察到撤销后如何处置已发送(在途)请求。
type LeaseMode int

const (
	// LeaseAbort 立即中止在途请求。
	LeaseAbort LeaseMode = iota
	// LeaseDrain 给在途请求一个排空租约, 超时仍未完成则中止。
	LeaseDrain
)

// LeaseConfig 配置撤销租约。
type LeaseConfig struct {
	Mode         LeaseMode
	DrainTimeout time.Duration
}

// Hooks 是测试屏障钩子。BeforeStreamOpen 在发送临界区内、最终授权复核
// 之前调用, 用于确定性复现"撤销与多路复用新流打开"的竞争。
type Hooks struct {
	BeforeStreamOpen func(id Identity)
	AfterAuthorize   func(id Identity, authorized bool)
}

type inflight struct {
	tenant string
	name   string
	cancel chan struct{}
	once   sync.Once
}

func (inf *inflight) abort() { inf.once.Do(func() { close(inf.cancel) }) }

// Config 组装侧车。
type Config struct {
	Engine   *Engine
	Resolver *Resolver
	Pool     *Pool
	Lease    LeaseConfig
	Hooks    Hooks
	ViaProxy bool // 实际连接是否经代理(计入授权身份)
}

// Sidecar 是本地出站授权侧车。
type Sidecar struct {
	engine   *Engine
	resolver *Resolver
	pool     *Pool
	lease    LeaseConfig
	viaProxy bool

	hooksMu sync.RWMutex
	hooks   Hooks

	// sendMu 串行化"发送"与"撤销观察": 发送持读锁, 撤销执行持写锁,
	// 保证观察到撤销之后不会再发出任何新请求。
	sendMu sync.RWMutex

	imu         sync.Mutex
	inflightSet map[*inflight]struct{}

	sub   <-chan RevokeEvent
	unsub func()
	done  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

func NewSidecar(cfg Config) *Sidecar {
	s := &Sidecar{
		engine:      cfg.Engine,
		resolver:    cfg.Resolver,
		pool:        cfg.Pool,
		lease:       cfg.Lease,
		viaProxy:    cfg.ViaProxy,
		hooks:       cfg.Hooks,
		inflightSet: map[*inflight]struct{}{},
		done:        make(chan struct{}),
	}
	if cfg.Pool != nil && cfg.Pool.Authorize == nil {
		cfg.Pool.Authorize = func(id Identity) error {
			_, err := cfg.Engine.Authorize(id.Tenant, id.Name)
			return err
		}
	}
	s.sub, s.unsub = cfg.Engine.Subscribe()
	s.wg.Add(1)
	go s.watchRevocations()
	return s
}

// SetHooks 在运行时替换测试钩子。
func (s *Sidecar) SetHooks(h Hooks) {
	s.hooksMu.Lock()
	s.hooks = h
	s.hooksMu.Unlock()
}

func (s *Sidecar) getHooks() Hooks {
	s.hooksMu.RLock()
	defer s.hooksMu.RUnlock()
	return s.hooks
}

// Close 停止撤销监听(幂等)。
func (s *Sidecar) Close() {
	s.once.Do(func() {
		close(s.done)
		s.unsub()
		s.wg.Wait()
	})
}

func (s *Sidecar) register(inf *inflight) {
	s.imu.Lock()
	s.inflightSet[inf] = struct{}{}
	s.imu.Unlock()
}

func (s *Sidecar) unregister(inf *inflight) {
	s.imu.Lock()
	delete(s.inflightSet, inf)
	s.imu.Unlock()
}

func (s *Sidecar) watchRevocations() {
	defer s.wg.Done()
	for {
		select {
		case <-s.done:
			return
		case ev := <-s.sub:
			s.enforce(ev)
		}
	}
}

// enforce 是撤销观察点: 拿到写锁期间不会有新发送进入临界区,
// 然后按租约配置中止或排空匹配的在途请求。
func (s *Sidecar) enforce(ev RevokeEvent) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.imu.Lock()
	var victims []*inflight
	for inf := range s.inflightSet {
		if inf.tenant == ev.Tenant && (ev.Name == "*" || inf.name == ev.Name) {
			victims = append(victims, inf)
		}
	}
	s.imu.Unlock()
	for _, inf := range victims {
		if s.lease.Mode == LeaseDrain {
			to := s.lease.DrainTimeout
			if to <= 0 {
				to = 100 * time.Millisecond
			}
			inf := inf
			time.AfterFunc(to, inf.abort)
		} else {
			inf.abort()
		}
	}
}

// Fetch 经授权路径获取文档, 跟随重定向(每跳重新授权、重新解析、重新确定身份)。
// 任何授权/系统失败都直接返回错误, 绝不退回直连。
func (s *Sidecar) Fetch(ctx context.Context, tenant, name, path string) (string, error) {
	hops := []string{}
	cur := name
	for hop := 0; hop < 5; hop++ {
		body, redirect, err := s.fetchOnce(ctx, tenant, cur, path, hops)
		if err != nil {
			return "", err
		}
		if redirect == "" {
			return body, nil
		}
		hops = append(hops, cur)
		cur = redirect
	}
	return "", ErrTooManyRedirects
}

func (s *Sidecar) fetchOnce(ctx context.Context, tenant, name, path string, hops []string) (body, redirect string, err error) {
	// 第一授权点: fail-closed。
	gen, err := s.engine.Authorize(tenant, name)
	if err != nil {
		return "", "", err
	}
	// 解析(迟到结果丢弃 + 有界重试)。
	res, err := s.resolver.Resolve(ctx, tenant, name, gen)
	if err != nil {
		return "", "", err
	}
	id := Identity{
		Tenant: tenant, Gen: gen, Name: name, Source: res.Source,
		Addr: res.Addr, ViaProxy: s.viaProxy,
		Hops: append(append([]string{}, hops...), name),
	}

	// 发送临界区: 与撤销观察互斥。借连接(可能新建, 拨号前再次授权)、
	// 屏障钩子、最终授权复核、打开多路复用流、写入请求, 全部在读锁内完成。
	s.sendMu.RLock()
	entry, err := s.pool.Borrow(ctx, id)
	if err != nil {
		s.sendMu.RUnlock()
		return "", "", err
	}
	hooks := s.getHooks()
	if hooks.BeforeStreamOpen != nil {
		hooks.BeforeStreamOpen(id)
	}
	_, authErr := s.engine.Authorize(tenant, name)
	if hooks.AfterAuthorize != nil {
		hooks.AfterAuthorize(id, authErr == nil)
	}
	if authErr != nil {
		s.sendMu.RUnlock()
		return "", "", authErr
	}
	st, err := entry.Sess.OpenStream()
	if err != nil {
		s.sendMu.RUnlock()
		return "", "", err
	}
	inf := &inflight{tenant: tenant, name: name, cancel: make(chan struct{})}
	s.register(inf)
	werr := st.Write(encodeRequest(id, entry.ConnID, path))
	if werr == nil {
		werr = st.CloseWrite()
	}
	s.sendMu.RUnlock()
	if werr != nil {
		s.unregister(inf)
		return "", "", werr
	}
	defer s.unregister(inf)

	type readRes struct {
		data []byte
		err  error
	}
	rc := make(chan readRes, 1)
	go func() {
		d, e := st.Read()
		rc <- readRes{d, e}
	}()
	select {
	case rr := <-rc:
		if rr.err != nil {
			return "", "", rr.err
		}
		return splitResponse(string(rr.data))
	case <-inf.cancel:
		// 租约到期/立即中止: 重置流并向调用方报告撤销。
		st.Reset()
		return "", "", ErrInflightRevoked
	case <-ctx.Done():
		st.Reset()
		return "", "", ctx.Err()
	}
}

func encodeRequest(id Identity, connID uint64, path string) []byte {
	via := "direct"
	if id.ViaProxy {
		via = "proxy"
	}
	return protocol.EncodeHeaders(map[string]string{
		"tenant": id.Tenant,
		"name":   id.Name,
		"gen":    strconv.FormatUint(id.Gen, 10),
		"source": id.Source,
		"addr":   id.Addr,
		"via":    via,
		"hops":   strings.Join(id.Hops, ">"),
		"hop":    strconv.Itoa(len(id.Hops) - 1),
		"idkey":  id.Key(),
		"connid": strconv.FormatUint(connID, 10),
		"path":   path,
		"target": id.Addr,
	})
}

func splitResponse(raw string) (body, redirect string, err error) {
	switch {
	case strings.HasPrefix(raw, "OK "):
		return strings.TrimPrefix(raw, "OK "), "", nil
	case strings.HasPrefix(raw, "REDIRECT "):
		return "", strings.TrimSpace(strings.TrimPrefix(raw, "REDIRECT ")), nil
	default:
		return "", "", fmt.Errorf("sidecar: upstream error: %s", raw)
	}
}
