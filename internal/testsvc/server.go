// Package testsvc 提供仅监听 127.0.0.1 的回环源站与转发代理,
// 二者都记录实际收到的请求(连接号、流号、头部), 供测试与参考模型比对授权判定。
// 本包不访问公网。
package testsvc

import (
	"net"
	"sync"

	"example.com/authsidecar/internal/protocol"
)

// ReceivedRequest 是服务端实际收到的一条请求记录。
type ReceivedRequest struct {
	ConnID  uint64
	Stream  uint32
	Headers map[string]string
}

// Server 是回环源站: 每条流一个请求/响应。
type Server struct {
	Name string
	ln   net.Listener

	// Handler 由请求头生成响应载荷 ("OK ..." / "REDIRECT <name>" / "ERR ...")。
	Handler func(h map[string]string) string
	// OnRequest 在记录日志之后、生成响应之前调用, 测试用它做确定性屏障。
	OnRequest func(h map[string]string)

	mu       sync.Mutex
	received []ReceivedRequest
	connSeq  uint64
}

func NewServer(name string, handler func(map[string]string) string) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{Name: name, ln: ln, Handler: handler}
	go s.acceptLoop()
	return s, nil
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

func (s *Server) Close() { _ = s.ln.Close() }

func (s *Server) Received() []ReceivedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ReceivedRequest(nil), s.received...)
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.connSeq++
		id := s.connSeq
		s.mu.Unlock()
		protocol.NewServerSession(c, func(st *protocol.Stream) { s.serve(id, st) })
	}
}

func (s *Server) serve(connID uint64, st *protocol.Stream) {
	raw, err := st.Read()
	if err != nil {
		return
	}
	h := protocol.ParseHeaders(string(raw))
	s.mu.Lock()
	s.received = append(s.received, ReceivedRequest{ConnID: connID, Stream: st.ID, Headers: h})
	s.mu.Unlock()
	if s.OnRequest != nil {
		s.OnRequest(h)
	}
	resp := "OK"
	if s.Handler != nil {
		resp = s.Handler(h)
	}
	_ = st.Write([]byte(resp))
	_ = st.CloseWrite()
	// 排空客户端的半关闭/重置, 避免 goroutine 泄漏。
	for {
		if _, err := st.Read(); err != nil {
			return
		}
	}
}

// Proxy 是测试转发代理: 侧车经它建立"实际连接", 它按 target 头转发到上游。
// 代理自身也记录收到的请求, 用于验证经由代理与直连的信任上下文不同。
type Proxy struct {
	ln net.Listener

	mu       sync.Mutex
	received []ReceivedRequest
	connSeq  uint64
}

func NewProxy() (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln}
	go p.acceptLoop()
	return p, nil
}

func (p *Proxy) Addr() string { return p.ln.Addr().String() }

func (p *Proxy) Close() { _ = p.ln.Close() }

func (p *Proxy) Received() []ReceivedRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ReceivedRequest(nil), p.received...)
}

func (p *Proxy) acceptLoop() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.connSeq++
		id := p.connSeq
		p.mu.Unlock()
		protocol.NewServerSession(c, func(st *protocol.Stream) { p.serve(id, st) })
	}
}

func (p *Proxy) serve(connID uint64, st *protocol.Stream) {
	raw, err := st.Read()
	if err != nil {
		return
	}
	h := protocol.ParseHeaders(string(raw))
	p.mu.Lock()
	p.received = append(p.received, ReceivedRequest{ConnID: connID, Stream: st.ID, Headers: h})
	p.mu.Unlock()

	up, err := net.Dial("tcp", h["target"])
	if err != nil {
		_ = st.Write([]byte("ERR proxy dial"))
		_ = st.CloseWrite()
		return
	}
	sess := protocol.NewClientSession(up)
	defer sess.Close()
	ust, err := sess.OpenStream()
	if err != nil {
		_ = st.Write([]byte("ERR proxy stream"))
		_ = st.CloseWrite()
		return
	}
	if err := ust.Write(raw); err == nil {
		err = ust.CloseWrite()
	}
	if err != nil {
		_ = st.Write([]byte("ERR proxy write"))
		_ = st.CloseWrite()
		return
	}
	resp, err := ust.Read()
	if err != nil {
		_ = st.Write([]byte("ERR upstream"))
	} else {
		_ = st.Write(resp)
	}
	_ = st.CloseWrite()
}
