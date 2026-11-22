// Package protocol 实现侧车与回环服务之间使用的帧协议与流多路复用会话。
// 一条物理连接(会话)上可承载多条并发流, 客户端发起奇数流号。
// 帧格式: [streamID uint32][op byte][length uint32][payload]。
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
)

const (
	opData  byte = 1 // 携带请求/响应载荷
	opClose byte = 2 // 半关闭: 对端不再发送数据
	opReset byte = 3 // 中止流(如租约撤销导致的在途取消)
)

const headerLen = 9

var (
	ErrSessionClosed = errors.New("protocol: session closed")
	ErrStreamReset   = errors.New("protocol: stream reset")
)

// Stream 是会话上的一条逻辑流。
type Stream struct {
	ID   uint32
	sess *Session

	recv     chan []byte
	done     chan struct{}
	doneOnce sync.Once
	err      error
}

func (s *Stream) Write(p []byte) error { return s.sess.writeFrame(s.ID, opData, p) }
func (s *Stream) CloseWrite() error    { return s.sess.writeFrame(s.ID, opClose, nil) }

// Reset 中止流: 通知对端并立即失败本地未完成的读。
func (s *Stream) Reset() {
	_ = s.sess.writeFrame(s.ID, opReset, nil)
	s.terminate(ErrStreamReset)
}

// Read 返回下一个 DATA 载荷; 对端半关闭且缓冲耗尽后返回 io.EOF。
func (s *Stream) Read() ([]byte, error) {
	p, ok := <-s.recv
	if !ok {
		if s.err != nil && s.err != io.EOF {
			return nil, s.err
		}
		return nil, io.EOF
	}
	return p, nil
}

func (s *Stream) deliver(p []byte) {
	defer func() { _ = recover() }() // 流可能已终止, 丢弃迟到数据
	s.recv <- p
}

func (s *Stream) terminate(err error) {
	s.doneOnce.Do(func() {
		s.err = err
		close(s.recv)
		close(s.done)
	})
}

// Session 是一条物理连接上的多路复用会话。
type Session struct {
	conn   net.Conn
	server bool
	accept func(*Stream)

	wmu sync.Mutex

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32

	closed    chan struct{}
	closeOnce sync.Once
}

func NewClientSession(conn net.Conn) *Session {
	s := &Session{conn: conn, streams: map[uint32]*Stream{}, nextID: 1, closed: make(chan struct{})}
	go s.readLoop()
	return s
}

func NewServerSession(conn net.Conn, accept func(*Stream)) *Session {
	s := &Session{conn: conn, server: true, accept: accept, streams: map[uint32]*Stream{}, nextID: 2, closed: make(chan struct{})}
	go s.readLoop()
	return s
}

// OpenStream 在(可能共享的)会话上借用一条新流。
func (s *Session) OpenStream() (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		return nil, ErrSessionClosed
	default:
	}
	id := s.nextID
	s.nextID += 2
	st := &Stream{ID: id, sess: s, recv: make(chan []byte, 16), done: make(chan struct{})}
	s.streams[id] = st
	return st, nil
}

func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		err = s.conn.Close()
		s.mu.Lock()
		for _, st := range s.streams {
			st.terminate(ErrSessionClosed)
		}
		s.mu.Unlock()
	})
	return err
}

func (s *Session) writeFrame(id uint32, op byte, p []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	select {
	case <-s.closed:
		return ErrSessionClosed
	default:
	}
	var hdr [headerLen]byte
	binary.BigEndian.PutUint32(hdr[0:4], id)
	hdr[4] = op
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(p)))
	if _, err := s.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(p) > 0 {
		_, err := s.conn.Write(p)
		return err
	}
	return nil
}

func (s *Session) readLoop() {
	defer s.Close()
	hdr := make([]byte, headerLen)
	for {
		if _, err := io.ReadFull(s.conn, hdr); err != nil {
			return
		}
		id := binary.BigEndian.Uint32(hdr[0:4])
		op := hdr[4]
		n := binary.BigEndian.Uint32(hdr[5:9])
		var p []byte
		if n > 0 {
			p = make([]byte, n)
			if _, err := io.ReadFull(s.conn, p); err != nil {
				return
			}
		}
		s.mu.Lock()
		st := s.streams[id]
		if st == nil && s.server && op == opData {
			st = &Stream{ID: id, sess: s, recv: make(chan []byte, 16), done: make(chan struct{})}
			s.streams[id] = st
			if s.accept != nil {
				acc := s.accept
				go acc(st)
			}
		}
		s.mu.Unlock()
		if st == nil {
			continue
		}
		switch op {
		case opData:
			st.deliver(p)
		case opClose:
			st.terminate(io.EOF)
		case opReset:
			st.terminate(ErrStreamReset)
		}
	}
}

// EncodeHeaders 把请求头编码为 "k: v\n" 行序列(键排序, 保证确定性)。
func EncodeHeaders(h map[string]string) []byte {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, h[k])
	}
	return []byte(b.String())
}

// ParseHeaders 解析 "k: v" 行序列。
func ParseHeaders(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		out[k] = v
	}
	return out
}
