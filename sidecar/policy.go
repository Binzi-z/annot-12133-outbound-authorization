package sidecar

import (
	"errors"
	"sync"
)

var (
	// ErrRevoked 表示授权身份已被撤销。撤销是append-only的, 策略回滚不会清除它。
	ErrRevoked = errors.New("sidecar: authorization revoked")
	// ErrNotAllowed 表示当前策略世代不允许该 (租户, 名称)。
	ErrNotAllowed = errors.New("sidecar: not allowed by policy")
	// ErrEngineFailure 表示策略引擎故障。侧车对此 fail-closed: 返回错误,
	// 绝不静默退回直连(侧车根本不存在直连回退路径)。
	ErrEngineFailure = errors.New("sidecar: policy engine failure (fail-closed)")
)

// RevokeEvent 是一次撤销观察。
type RevokeEvent struct {
	Tenant string
	Name   string // "*" 表示该租户的全部名称
}

// Engine 是策略引擎: 保存当前策略世代、允许表与单调递增的撤销集。
type Engine struct {
	mu      sync.Mutex
	gen     uint64
	allow   map[string]map[string]bool
	revoked map[string]map[string]bool // 撤销集: 跨策略回滚持久存在
	failed  bool

	subs   map[int]chan RevokeEvent
	subSeq int
}

func NewEngine(gen uint64, allow map[string]map[string]bool) *Engine {
	return &Engine{
		gen:     gen,
		allow:   allow,
		revoked: map[string]map[string]bool{},
		subs:    map[int]chan RevokeEvent{},
	}
}

func (e *Engine) Gen() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gen
}

// Authorize 判定 (tenant, name) 在当前状态下是否被授权, 返回观察到的策略世代。
// 引擎故障时返回 ErrEngineFailure, 调用方必须 fail-closed。
func (e *Engine) Authorize(tenant, name string) (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return 0, ErrEngineFailure
	}
	if e.revoked[tenant]["*"] || e.revoked[tenant][name] {
		return 0, ErrRevoked
	}
	if !e.allow[tenant][name] {
		return 0, ErrNotAllowed
	}
	return e.gen, nil
}

// IsRevoked 报告 (tenant, name) 是否已被撤销(供解析器丢弃迟到结果)。
func (e *Engine) IsRevoked(tenant, name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.revoked[tenant]["*"] || e.revoked[tenant][name]
}

// Revoke 记录一次撤销并通知订阅者。撤销立即生效且不可通过策略回滚抹除。
func (e *Engine) Revoke(tenant, name string) {
	e.mu.Lock()
	if e.revoked[tenant] == nil {
		e.revoked[tenant] = map[string]bool{}
	}
	e.revoked[tenant][name] = true
	subs := make([]chan RevokeEvent, 0, len(e.subs))
	for _, ch := range e.subs {
		subs = append(subs, ch)
	}
	e.mu.Unlock()
	ev := RevokeEvent{Tenant: tenant, Name: name}
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// SetPolicy 安装新的策略世代。允许回滚到更旧的世代, 但撤销集是
// append-only 的: 回滚不会恢复已被撤销的权限。
func (e *Engine) SetPolicy(gen uint64, allow map[string]map[string]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gen = gen
	e.allow = allow
}

// SetFailed 注入/清除引擎故障(用于验证 fail-closed)。
func (e *Engine) SetFailed(f bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failed = f
}

// Subscribe 订阅撤销事件, 返回的函数用于退订。
func (e *Engine) Subscribe() (<-chan RevokeEvent, func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.subSeq++
	ch := make(chan RevokeEvent, 64)
	e.subs[e.subSeq] = ch
	id := e.subSeq
	return ch, func() {
		e.mu.Lock()
		delete(e.subs, id)
		e.mu.Unlock()
	}
}
