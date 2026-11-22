# 本地出站授权侧车与文档同步测试客户端

一个纯 Go 标准库实现的参考系统: 所有出站请求都经过本地授权侧车,
连接在同一授权域内可复用与多路复用, 但**授权身份**决定信任上下文;
撤销有明确边界; 系统故障一律 fail-closed, 不存在静默直连回退。
全部测试仅使用 `127.0.0.1` 回环, 不访问公网。

## 运行

```sh
go test ./...          # 全部测试(含 1320 条两租户交错的参考模型重放)
go test -short ./...   # 采样交错子集, 快速冒烟
```

## 结构

| 包 | 职责 |
|---|---|
| `internal/protocol` | 帧协议与流多路复用会话(一条连接承载多条并发流) |
| `internal/testsvc`  | 回环源站与转发代理, 均记录**实际接收日志**(连接号/流号/头部) |
| `sidecar`           | 授权身份、策略引擎、解析器、分片连接池、侧车本体 |
| `client`            | 文档同步测试客户端(只有侧车一条出站路径) |
| `model`             | 可执行参考模型: 事件、oracle、交错枚举 + 屏障驱动重放比对 |

## 授权身份

`sidecar.Identity` 由六要素共同决定, 任一不同即不同的信任上下文:

1. **租户** (Tenant)
2. **策略世代** (Gen, 授权时观察到的世代)
3. **原始名称** (Name, 解析前)
4. **解析来源** (Source) 与解析得到的地址 (Addr)
5. **实际连接** (直连 / 经代理)
6. **每一跳重定向** (Hops 名称链)

身份的散列是连接池键: **同一目标地址、不同身份的请求落在不同的池项上,
不能借用对方的连接**(`TestIdentityIsolation`)。重定向的每一跳都重新授权、
重新解析、生成新身份、使用新连接(`TestRedirectReauthorization`)。

## 撤销边界

- 策略引擎(`sidecar.Engine`)的撤销集是 **append-only** 的:
  `SetPolicy` 允许回滚/前滚世代, 但**回滚不恢复已撤销权限**
  (`TestPolicyRollbackDoesNotRestoreRevocation`)。
- 发送临界区(`sendMu` 读写锁)串行化"发送"与"撤销观察":
  **观察到撤销后禁止发出新请求**; 临界区内还有最终授权复核,
  挡住"复核通过→撤销→开流"窗口。
- 已发送(在途)请求按可配置租约处置:
  `LeaseAbort` 立即重置流; `LeaseDrain` 给排空租约, 超时再中止
  (`TestRevocationBoundaryAbort` / `TestRevocationBoundaryDrain`)。
- 撤销执行按 (租户, 名称) 精确匹配在途请求, `*` 为租户级通配;
  租户间互不影响。

## 解析与连接池

- **迟到解析丢弃**: 解析结果交付前重新校验策略世代与撤销状态,
  期间世界已变则丢弃(`ErrStaleResolution`, `TestLateResolutionDiscarded`)。
- **有界重试**: 后端失败最多 `MaxAttempts` 次, 带退避
  (`TestBoundedRetry`)。
- **分片连接池**: 按租户 FNV 散列到 16 个分片, 分片内按身份散列;
  并发建立去重, 同身份复用同一会话的不同流(`TestMuxStreamReuse`)。

## Fail-closed

策略引擎故障、解析失败、拨号失败都直接返回错误; 侧车与客户端
**没有直连回退路径**。`TestEngineFailureFailsClosed` 断言引擎故障时
零拨号、服务端零接收。

## 可执行参考模型

`model` 包把场景建模为偏序事件集:

- 事件: **连接建立 / 流借用 / 重定向 / 撤销 / 响应到达**, 两租户交错;
- `Enumerate` 枚举全部拓扑序(A 链含一跳重定向共 7 事件、B 链 3 事件、
  撤销 1 事件 → **1320 种交错**);
- `Replay` 给出 oracle: 撤销之后的借用不得发出请求;
- `model_test.runTrace` 用**确定性屏障**(拨号前/开流前/响应前钩子 +
  每事件 gate/reached 通道对)把真实并发系统驱动到指定交错,
  然后比对: 侧车对每个借用的实际授权判定 == oracle 判定, 且
  **服务端实际接收日志 == oracle 授权集合(不多不少)**。

## 确定性竞争复现

`TestRevokeVsMuxStreamOpenRace`: 第一次请求让连接入池; 第二次请求复用
该多路复用会话, `BeforeStreamOpen` 屏障把新流打开卡在最终授权复核之前;
此时注入撤销再放行 —— 复核必须拒绝, 服务端不得看到新请求。

## 测试代理与回环服务

`testsvc.Server` 是回环源站(每流一个请求/响应, 支持 `REDIRECT`);
`testsvc.Proxy` 按 `target` 头转发并各自记录接收日志。
`TestProxyPath` 验证经代理的实际连接计入身份(`via: proxy`)。
