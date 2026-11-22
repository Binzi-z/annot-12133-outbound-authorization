// Package client 提供文档同步测试客户端。客户端只通过侧车出站,
// 没有任何直连路径, 因此授权/系统故障不可能静默退回直连。
package client

import (
	"context"

	"example.com/authsidecar/sidecar"
)

// DocSync 是文档同步测试客户端。
type DocSync struct {
	Sidecar *sidecar.Sidecar
	Tenant  string
}

// Sync 依次同步给定文档。任一文档失败(撤销、未授权、引擎故障等)都会
// 中止同步并返回错误 —— 客户端不存在绕过侧车的回退。
func (c *DocSync) Sync(ctx context.Context, docs []string) (map[string]string, error) {
	out := make(map[string]string, len(docs))
	for _, d := range docs {
		body, err := c.Sidecar.Fetch(ctx, c.Tenant, d, "/"+d)
		if err != nil {
			return nil, err
		}
		out[d] = body
	}
	return out, nil
}
