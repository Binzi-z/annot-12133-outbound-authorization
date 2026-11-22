package server

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"egressz/authz"
	"egressz/mux"
	"egressz/policy"
)

// AuthzProxy is a loopback mux authorization proxy. Every accepted mux
// connection authenticates the Hello ConnID and every stream's HMAC token, then
// independently evaluates the full identity against its policy bundle before
// any byte is forwarded. The decision is appended to the shared receive-log,
// giving the tests an authoritative record to compare against.
type AuthzProxy struct {
	name   string
	addr   string
	secret []byte
	ln     net.Listener
	log    *DecisionLog
	origin string // loopback origin address (empty for redirect-only proxies)

	mu     sync.RWMutex
	bundle policy.Bundle
	loaded bool

	redirectTo string // when set, authorized streams answer with a redirect frame
	closeOnce  sync.Once
}

// ProxyConfig configures an AuthzProxy.
type ProxyConfig struct {
	Name       string
	Secret     []byte
	Log        *DecisionLog
	Origin     string
	RedirectTo string
}

// NewAuthzProxy starts a proxy on an ephemeral loopback port.
func NewAuthzProxy(cfg ProxyConfig) (*AuthzProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &AuthzProxy{
		name:       cfg.Name,
		addr:       ln.Addr().String(),
		secret:     cfg.Secret,
		ln:         ln,
		log:        cfg.Log,
		origin:     cfg.Origin,
		redirectTo: cfg.RedirectTo,
	}
	go p.acceptLoop()
	return p, nil
}

// Addr returns the proxy's loopback dial address.
func (p *AuthzProxy) Addr() string { return p.addr }

// Name returns the proxy label used in the receive log.
func (p *AuthzProxy) Name() string { return p.name }

// SetBundle swaps the policy view used for independent server-side decisions.
func (p *AuthzProxy) SetBundle(b policy.Bundle) {
	p.mu.Lock()
	p.bundle = b
	p.loaded = true
	p.mu.Unlock()
}

// Close stops the listener.
func (p *AuthzProxy) Close() error {
	var err error
	p.closeOnce.Do(func() { err = p.ln.Close() })
	return err
}

func (p *AuthzProxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.serveConn(conn)
	}
}

func (p *AuthzProxy) serveConn(conn net.Conn) {
	sess, err := mux.Server(conn, p.secret, p.verify, p.record)
	if err != nil {
		conn.Close()
		return
	}
	for {
		st, id, err := sess.Accept()
		if err != nil {
			return
		}
		go p.serveStream(st, id)
	}
}

// verify is invoked inside mux handleAuth after MAC and ConnID binding checks.
func (p *AuthzProxy) verify(id authz.Identity) error {
	p.mu.RLock()
	bundle := p.bundle
	loaded := p.loaded
	p.mu.RUnlock()
	if !loaded {
		// Server-side fail closed: no policy loaded means deny.
		return errors.New("server_no_policy_loaded")
	}
	res := policy.Evaluate(bundle, id)
	if res.Decision != policy.Allow {
		return errors.New(res.Reason)
	}
	return nil
}

// record is the mux DecisionLogger; it also captures MAC/binding failures
// (which arrive with a zero identity).
func (p *AuthzProxy) record(id authz.Identity, allowed bool, reason string) {
	p.log.Record(p.name, id, allowed, reason)
}

func (p *AuthzProxy) serveStream(st *mux.Stream, id authz.Identity) {
	body, err := io.ReadAll(st)
	if err != nil {
		_ = st.Close()
		return
	}

	// Re-check identity at forwarding time; a policy change between auth and
	// data arrival must not slip through.
	if err := p.verify(id); err != nil {
		_ = st.SendReset("recheck:" + err.Error())
		return
	}

	if p.redirectTo != "" {
		// Authorized, but this proxy is a redirect hop.
		_ = st.SendRedirect(p.redirectTo)
		return
	}
	if p.origin == "" {
		_ = st.SendReset("no_origin_configured")
		return
	}

	// Forward over a fresh, loopback-only plain TCP connection to the origin.
	originConn, err := net.DialTimeout("tcp", p.origin, 2*time.Second)
	if err != nil {
		_ = st.SendReset("origin_unreachable")
		return
	}
	defer originConn.Close()
	if _, err := originConn.Write(body); err != nil {
		_ = st.SendReset("origin_write_failed")
		return
	}
	_ = originConn.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(originConn)
	if err != nil {
		_ = st.SendReset("origin_read_failed")
		return
	}
	if _, err := st.Write(reply); err != nil {
		return
	}
	_ = st.CloseWrite()
}
