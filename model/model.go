// Package model 是可执行参考模型: 把两租户场景中的关键事件
// (连接建立、流借用、重定向、撤销、响应到达)建模为偏序集,
// 枚举其全部拓扑交错, 并为每条轨迹提供授权判定 oracle。
// model_test 中的屏障驱动执行器把每条轨迹在真实侧车+回环服务上重放,
// 再用服务端实际接收日志与 oracle 的判定比对。
package model

// Kind 是事件类型。
type Kind int

const (
	Connect  Kind = iota // 为某身份建立连接
	Borrow               // 在(可能共享的)多路复用会话上尝试借用新流
	Response             // 服务端收到请求并产生响应
	Revoke               // 观察到撤销
	Redirect             // 客户端处理一跳重定向(标记事件, 不占屏障)
)

func (k Kind) String() string {
	switch k {
	case Connect:
		return "Connect"
	case Borrow:
		return "Borrow"
	case Response:
		return "Response"
	case Revoke:
		return "Revoke"
	case Redirect:
		return "Redirect"
	}
	return "?"
}

// Event 是轨迹中的一个事件。ID 是规范事件表中的稳定编号;
// Occ 是同一 (租户, 类型) 的出现序号(如重定向后第二跳为 2)。
type Event struct {
	ID     int
	Kind   Kind
	Tenant string
	Occ    int
}

// Oracle 重放一条轨迹并给出每个 Borrow 事件的授权判定。
type Oracle struct {
	revoked map[string]bool
	auth    map[int]bool // 事件 ID -> 是否授权发送
}

// Replay 按轨迹顺序计算授权判定: Borrow 之前若已观察到该租户的撤销,
// 则该借用不得发出请求。
func Replay(trace []Event) *Oracle {
	o := &Oracle{revoked: map[string]bool{}, auth: map[int]bool{}}
	for _, e := range trace {
		switch e.Kind {
		case Revoke:
			o.revoked[e.Tenant] = true
		case Borrow:
			o.auth[e.ID] = !o.revoked[e.Tenant]
		}
	}
	return o
}

// Authorized 返回 oracle 对某个 Borrow 事件的判定。
func (o *Oracle) Authorized(id int) bool { return o.auth[id] }

// Reachable 报告事件在轨迹位置上是否可能真实发生: 一旦该租户此前已被
// 撤销, 其后续的连接/借用/响应链都会停滞(侧车 fail-closed)。
func (o *Oracle) Reachable(trace []Event, i int) bool {
	for j := 0; j < i; j++ {
		if trace[j].Kind == Revoke && trace[j].Tenant == trace[i].Tenant {
			return false
		}
	}
	return true
}

// Enumerate 枚举事件集在偏序约束(edges 为索引对 before->after)下的
// 全部拓扑序, 即所有合法交错。
func Enumerate(events []Event, edges [][2]int) [][]Event {
	indeg := make([]int, len(events))
	adj := map[int][]int{}
	for _, e := range edges {
		adj[e[0]] = append(adj[e[0]], e[1])
		indeg[e[1]]++
	}
	var out [][]Event
	cur := make([]Event, 0, len(events))
	used := make([]bool, len(events))
	var rec func()
	rec = func() {
		if len(cur) == len(events) {
			out = append(out, append([]Event(nil), cur...))
			return
		}
		for i := range events {
			if used[i] || indeg[i] != 0 {
				continue
			}
			used[i] = true
			cur = append(cur, events[i])
			for _, j := range adj[i] {
				indeg[j]--
			}
			rec()
			for _, j := range adj[i] {
				indeg[j]++
			}
			cur = cur[:len(cur)-1]
			used[i] = false
		}
	}
	rec()
	return out
}
