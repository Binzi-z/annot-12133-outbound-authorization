package sidecar

import (
	"context"
	"errors"
	"time"
)

// ErrStaleResolution 表示解析结果返回时世界已经改变(策略世代前进或发生撤销),
// 该迟到结果必须被丢弃而不是被使用。
var ErrStaleResolution = errors.New("sidecar: stale resolution discarded")

// Backend 是名称解析后端(测试中用模拟 DNS, 不访问公网)。
type Backend interface {
	Lookup(name string) (string, error)
}

// BackendFunc 适配函数到 Backend。
type BackendFunc func(name string) (string, error)

func (f BackendFunc) Lookup(name string) (string, error) { return f(name) }

// Resolution 是一次成功且未过期的解析结果。
type Resolution struct {
	Name   string
	Addr   string
	Source string
	Gen    uint64 // 解析所针对的策略世代
}

// Resolver 执行带迟到丢弃与有界重试的名称解析。
type Resolver struct {
	Engine      *Engine
	Backend     Backend
	Source      string // 解析来源, 计入授权身份
	Latency     time.Duration
	MaxAttempts int // 有界重试: 最大尝试次数(含首次)
	Backoff     time.Duration

	// BeforeAttempt 是测试钩子, 在每次尝试前调用。
	BeforeAttempt func(name string, attempt int)
}

// Resolve 解析 name。每次尝试后、结果交付前都重新校验:
// 若期间策略世代变化或 (tenant, name) 被撤销, 则丢弃结果并返回 ErrStaleResolution。
// 后端失败按 MaxAttempts 有界重试。
func (r *Resolver) Resolve(ctx context.Context, tenant, name string, gen uint64) (Resolution, error) {
	max := r.MaxAttempts
	if max <= 0 {
		max = 1
	}
	var lastErr error
	for attempt := 1; attempt <= max; attempt++ {
		if r.BeforeAttempt != nil {
			r.BeforeAttempt(name, attempt)
		}
		if r.Latency > 0 {
			select {
			case <-ctx.Done():
				return Resolution{}, ctx.Err()
			case <-time.After(r.Latency):
			}
		}
		addr, err := r.Backend.Lookup(name)
		if err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return Resolution{}, ctx.Err()
			case <-time.After(r.Backoff):
			}
			continue
		}
		// 迟到解析丢弃: 解析期间世界已经改变, 结果不得使用。
		if r.Engine != nil {
			if r.Engine.Gen() != gen || r.Engine.IsRevoked(tenant, name) {
				return Resolution{}, ErrStaleResolution
			}
		}
		return Resolution{Name: name, Addr: addr, Source: r.Source, Gen: gen}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("sidecar: resolution failed")
	}
	return Resolution{}, lastErr
}
