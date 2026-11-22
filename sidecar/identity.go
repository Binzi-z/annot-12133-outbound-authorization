package sidecar

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// Identity 是一个请求的完整授权身份。同一授权域内的连接可以复用与多路复用,
// 但身份由以下要素共同决定, 任一不同即属于不同的信任上下文:
//   - Tenant:   租户
//   - Gen:      授权时观察到的策略世代
//   - Name:     原始名称(解析前)
//   - Source:   解析来源(如 simdns / hosts / cache)
//   - Addr:     解析得到的目标地址
//   - ViaProxy: 实际连接路径(直连或经代理)
//   - Hops:     每一跳重定向的名称链(含当前跳)
type Identity struct {
	Tenant   string
	Gen      uint64
	Name     string
	Source   string
	Addr     string
	ViaProxy bool
	Hops     []string
}

// Key 是身份的规范化散列, 用作连接池键: 同一目标地址但身份不同的请求
// 落在不同的池项上, 不能借用对方的连接/信任上下文。
func (id Identity) Key() string {
	sum := sha1.Sum([]byte(fmt.Sprintf("%s|%d|%s|%s|%s|%v|%s",
		id.Tenant, id.Gen, id.Name, id.Source, id.Addr, id.ViaProxy,
		strings.Join(id.Hops, ">"))))
	return hex.EncodeToString(sum[:])
}
