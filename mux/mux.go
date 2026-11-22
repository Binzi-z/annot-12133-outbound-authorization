// Package mux is a small framed stream multiplexer over a single net.Conn.
//
// Frame layout (big endian):
//
//	type     uint8
//	streamID uint32
//	length   uint32
//	payload  [length]byte
//
// The client begins every connection with a Hello frame (stream 0) carrying the
// per-connection ConnID. The first frame of every new stream is an Auth frame
// carrying an HMAC token whose identity is bound to that same ConnID; the
// server verifies the binding before the stream is accepted. A token minted for
// another connection cannot be replayed here.
package mux

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"egressz/authz"
)

// Frame type constants.
const (
	FrameHello    = frameHello
	FrameAuth     = frameAuth
	FrameData     = frameData
	FrameFin      = frameFin
	FrameRst      = frameRst
	FrameRedirect = frameRedirect
)

const (
	frameHello = iota + 1
	frameAuth
	frameData
	frameFin
	frameRst
	frameRedirect
)

const (
	headerSize = 9
	maxPayload = 1 << 20 // 1 MiB per frame
)

// Errors returned by streams and sessions.
var (
	ErrSessionClosed = errors.New("mux: session closed")
	ErrStreamReset   = errors.New("mux: stream reset")
	ErrRedirected    = errors.New("mux: stream redirected")
	ErrBadHandshake  = errors.New("mux: bad handshake")
	ErrDeadline      = errors.New("mux: i/o timeout")
)

// Verifier authenticates and authorizes a stream identity on the server side.
// It returns nil to accept the stream.
type Verifier func(id authz.Identity) error

// DecisionLogger records the server-side allow/deny verdict for every stream.
type DecisionLogger func(id authz.Identity, allowed bool, reason string)

// Session is one multiplexed connection.
type Session struct {
	conn     net.Conn
	isClient bool
	connID   string
	secret   []byte

	writeMu sync.Mutex
	readMu  sync.Mutex // serializes raw conn reads

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	closed  bool
	closeCh chan struct{}

	acceptCh chan accepted
	verifier Verifier
	logger   DecisionLogger
}

type accepted struct {
	st *Stream
	id authz.Identity
}

// Stream is one logical flow inside a Session.
type Stream struct {
	sess *Session
	id   uint32

	mu        sync.Mutex
	cond      *sync.Cond
	buf       bytes.Buffer
	readErr   error
	writeDone bool
	readDone  bool
	deadline  time.Time
	deadTimer *time.Timer

	redirectTo string
	authSent   bool
}

// Dial performs the client handshake over conn and returns a client Session.
func Dial(conn net.Conn, connID string) (*Session, error) {
	s := newSession(conn, true)
	s.connID = connID
	if err := s.writeFrameRaw(frameHello, 0, []byte(connID)); err != nil {
		conn.Close()
		return nil, err
	}
	go s.readLoop()
	return s, nil
}

// Server performs the server handshake and returns a server Session.
func Server(conn net.Conn, secret []byte, verifier Verifier, logger DecisionLogger) (*Session, error) {
	s := newSession(conn, false)
	s.secret = secret
	s.verifier = verifier
	s.logger = logger
	typ, sid, payload, err := s.readFrameRaw()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if typ != frameHello || sid != 0 {
		conn.Close()
		return nil, ErrBadHandshake
	}
	s.connID = string(payload)
	go s.readLoop()
	return s, nil
}

func newSession(conn net.Conn, isClient bool) *Session {
	s := &Session{
		conn:     conn,
		isClient: isClient,
		streams:  map[uint32]*Stream{},
		nextID:   1,
		closeCh:  make(chan struct{}),
		acceptCh: make(chan accepted, 64),
	}
	return s
}

// ConnID returns the connection identifier exchanged in the handshake.
func (s *Session) ConnID() string { return s.connID }

// RemoteAddr exposes the underlying peer address.
func (s *Session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// Open creates a new client stream. The Auth frame is sent lazily by
// SendAuth so callers can attach the exact identity token.
func (s *Session) Open() (*Stream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	id := s.nextID
	s.nextID++
	st := &Stream{sess: s, id: id}
	st.cond = sync.NewCond(&st.mu)
	s.streams[id] = st
	s.mu.Unlock()
	return st, nil
}

// SendAuth emits the authenticated identity as the first stream frame.
func (st *Stream) SendAuth(tok authz.Token) error {
	raw, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	st.mu.Lock()
	st.authSent = true
	st.mu.Unlock()
	return st.sess.writeFrame(frameAuth, st.id, raw)
}

// Accept blocks until the next authorized stream arrives.
func (s *Session) Accept() (*Stream, authz.Identity, error) {
	select {
	case a, ok := <-s.acceptCh:
		if !ok {
			return nil, authz.Identity{}, ErrSessionClosed
		}
		return a.st, a.id, nil
	case <-s.closeCh:
		return nil, authz.Identity{}, ErrSessionClosed
	}
}

// Read implements io.Reader.
func (st *Stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	for st.buf.Len() == 0 && st.readErr == nil {
		if !st.deadline.IsZero() && !time.Now().Before(st.deadline) {
			st.mu.Unlock()
			return 0, ErrDeadline
		}
		st.cond.Wait()
	}
	if st.buf.Len() > 0 {
		n, _ := st.buf.Read(p)
		st.mu.Unlock()
		return n, nil
	}
	err := st.readErr
	st.mu.Unlock()
	return 0, err
}

// Write sends a data frame.
func (st *Stream) Write(p []byte) (int, error) {
	if err := st.sess.writeFrame(frameData, st.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite signals end of the request body (half close).
func (st *Stream) CloseWrite() error {
	return st.sess.writeFrame(frameFin, st.id, nil)
}

// ID returns the stream identifier.
func (st *Stream) ID() uint32 { return st.id }

// SendRedirect tells the peer to follow target (server side).
func (st *Stream) SendRedirect(target string) error {
	return st.sess.writeFrame(frameRedirect, st.id, []byte(target))
}

// SendReset tears the stream down with a reason (server side).
func (st *Stream) SendReset(reason string) error {
	st.sess.removeStream(st.id)
	return st.sess.writeFrame(frameRst, st.id, []byte(reason))
}

// Close tears down the stream with a reset.
func (st *Stream) Close() error {
	st.sess.removeStream(st.id)
	_ = st.sess.writeFrame(frameRst, st.id, []byte("closed"))
	st.fail(ErrStreamReset)
	return nil
}

// SetReadDeadline sets an absolute deadline for Read.
func (st *Stream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.deadline = t
	if st.deadTimer != nil {
		st.deadTimer.Stop()
		st.deadTimer = nil
	}
	if !t.IsZero() {
		d := time.Until(t)
		if d > 0 {
			st.deadTimer = time.AfterFunc(d, func() {
				st.mu.Lock()
				st.cond.Broadcast()
				st.mu.Unlock()
			})
		}
	}
	st.mu.Unlock()
	return nil
}

// RedirectTarget returns the redirect address once ErrRedirected is observed.
func (st *Stream) RedirectTarget() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.redirectTo
}

func (st *Stream) fail(err error) {
	st.mu.Lock()
	if st.readErr == nil {
		st.readErr = err
	}
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) appendData(p []byte) {
	st.mu.Lock()
	st.buf.Write(p)
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) markFin() {
	st.mu.Lock()
	if st.readErr == nil {
		st.readErr = io.EOF
	}
	st.readDone = true
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// Close terminates the session and every stream on it.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	streams := s.streams
	s.streams = map[uint32]*Stream{}
	close(s.acceptCh)
	s.mu.Unlock()
	for _, st := range streams {
		st.fail(ErrSessionClosed)
	}
	return s.conn.Close()
}

// Closed reports whether the session is shutting down.
func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) writeFrame(typ uint8, sid uint32, payload []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	s.mu.Unlock()
	return s.writeFrameRaw(typ, sid, payload)
}

func (s *Session) writeFrameRaw(typ uint8, sid uint32, payload []byte) error {
	if len(payload) > maxPayload {
		return fmt.Errorf("mux: frame too large: %d", len(payload))
	}
	hdr := make([]byte, headerSize)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], sid)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) readFrameRaw() (typ uint8, sid uint32, payload []byte, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	hdr := make([]byte, headerSize)
	if _, err = io.ReadFull(s.conn, hdr); err != nil {
		return 0, 0, nil, err
	}
	typ = hdr[0]
	sid = binary.BigEndian.Uint32(hdr[1:5])
	n := binary.BigEndian.Uint32(hdr[5:9])
	if n > maxPayload {
		return 0, 0, nil, fmt.Errorf("mux: frame too large: %d", n)
	}
	payload = make([]byte, n)
	if n > 0 {
		if _, err = io.ReadFull(s.conn, payload); err != nil {
			return 0, 0, nil, err
		}
	}
	return typ, sid, payload, nil
}

func (s *Session) readLoop() {
	defer s.Close()
	for {
		typ, sid, payload, err := s.readFrameRaw()
		if err != nil {
			return
		}
		if sid == 0 && typ == frameHello {
			continue // hello handled at handshake; ignore repeats
		}
		if !s.isClient && typ == frameAuth {
			s.handleAuth(sid, payload)
			continue
		}
		s.mu.Lock()
		st, ok := s.streams[sid]
		s.mu.Unlock()
		if !ok {
			// Unknown stream: send reset so the peer cleans up.
			_ = s.writeFrame(frameRst, sid, []byte("unknown_stream"))
			continue
		}
		switch typ {
		case frameData:
			st.appendData(payload)
		case frameFin:
			st.markFin()
		case frameRst:
			s.removeStream(sid)
			st.fail(fmt.Errorf("%w: %s", ErrStreamReset, string(payload)))
		case frameRedirect:
			st.mu.Lock()
			st.redirectTo = string(payload)
			st.mu.Unlock()
			st.fail(ErrRedirected)
		}
	}
}

func (s *Session) handleAuth(sid uint32, payload []byte) {
	id, err := authz.VerifyToken(s.secret, payload)
	allowed := err == nil
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	if allowed && id.ConnID != s.connID {
		allowed = false
		reason = "conn_id_mismatch:token=" + id.ConnID + " session=" + s.connID
		err = errors.New(reason)
	}
	if allowed && s.verifier != nil {
		if verr := s.verifier(id); verr != nil {
			allowed = false
			reason = verr.Error()
			err = verr
		}
	}
	if s.logger != nil {
		s.logger(id, allowed, reason)
	}
	if !allowed {
		_ = s.writeFrame(frameRst, sid, []byte(reason))
		return
	}
	st := &Stream{sess: s, id: sid, authSent: true}
	st.cond = sync.NewCond(&st.mu)
	s.mu.Lock()
	s.streams[sid] = st
	s.mu.Unlock()
	s.acceptCh <- accepted{st: st, id: id}
}
