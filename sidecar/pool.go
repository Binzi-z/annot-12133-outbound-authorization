package sidecar

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"sync"

	"example.com/authsidecar/internal/protocol"
)

// Entry 是池中的一条已建立连接(多路复用会话), 绑定唯一的授权身份。
type Entry struct {
	ID     Identity
	ConnID uint64
	Sess   *protocol.Session
}

type shard struct {
	mu    sync.Mutex
	conns map[string]*Entry
}

// Pool 是分片连接池: 按租户散列到 16 个分片以降低锁竞争,
// 分片内以完整身份散列为键。同一目标地址、不同身份的请求得到不同的
// Entry, 因此绝不共享信任上下文。
type Pool struct {
	shards  [16]shard
	seqMu   sync.Mutex
	connSeq uint64

	// Dial 建立物理连接(直连或经代理, 由构造方决定)。
	Dial func(ctx context.Context, id Identity) (net.Conn, error)

	// Authorize 在真正拨号前重新校验身份(连接建立也是授权边界)。
	Authorize func(id Identity) error

	// BeforeDial / AfterDial 是测试屏障钩子, 用于确定性复现交错。
	BeforeDial func(id Identity)
	AfterDial  func(id Identity)
}

func NewPool(dial func(context.Context, Identity) (net.Conn, error)) *Pool {
	p := &Pool{Dial: dial}
	for i := range p.shards {
		p.shards[i].conns = map[string]*Entry{}
	}
	return p
}

func (p *Pool) shardFor(tenant string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tenant))
	return &p.shards[h.Sum32()%uint32(len(p.shards))]
}

// Borrow 借用身份 id 对应的连接, 不存在则建立。借用方随后在 Entry.Sess
// 上打开新流(多路复用)。
func (p *Pool) Borrow(ctx context.Context, id Identity) (*Entry, error) {
	key := id.Key()
	sh := p.shardFor(id.Tenant)

	sh.mu.Lock()
	if e, ok := sh.conns[key]; ok {
		sh.mu.Unlock()
		return e, nil
	}
	sh.mu.Unlock()

	if p.BeforeDial != nil {
		p.BeforeDial(id)
	}
	if p.Authorize != nil {
		if err := p.Authorize(id); err != nil {
			return nil, err
		}
	}
	conn, err := p.Dial(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("sidecar: dial: %w", err)
	}
	if p.AfterDial != nil {
		p.AfterDial(id)
	}

	p.seqMu.Lock()
	p.connSeq++
	seq := p.connSeq
	p.seqMu.Unlock()
	e := &Entry{ID: id, ConnID: seq, Sess: protocol.NewClientSession(conn)}

	sh.mu.Lock()
	if old, ok := sh.conns[key]; ok {
		// 并发建立去重: 关闭多余连接, 复用先入池者。
		sh.mu.Unlock()
		_ = e.Sess.Close()
		return old, nil
	}
	sh.conns[key] = e
	sh.mu.Unlock()
	return e, nil
}

// ConnCount 返回池中连接总数(测试用于验证身份隔离与复用)。
func (p *Pool) ConnCount() int {
	n := 0
	for i := range p.shards {
		p.shards[i].mu.Lock()
		n += len(p.shards[i].conns)
		p.shards[i].mu.Unlock()
	}
	return n
}
