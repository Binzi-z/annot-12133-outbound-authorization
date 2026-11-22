package sidecar

import (
	"io"
	"net"
	"net/http"
)

// HeaderTenant and HeaderDoc carry the request's authorization inputs on the
// loopback HTTP proxy interface.
const (
	HeaderTenant = "X-Egress-Tenant"
	HeaderDoc    = "X-Egress-Doc"
)

// ProxyListener is the sidecar's local HTTP egress endpoint. Local workloads
// (the document sync client included) POST here; the sidecar performs the full
// authorize / pool / redirect / revoke flow and never exposes the upstream
// proxies or origin to the caller.
type ProxyListener struct {
	sc  *Sidecar
	ln  net.Listener
	srv *http.Server
}

// ServeProxy starts the loopback HTTP proxy and returns its wrapper.
func ServeProxy(sc *Sidecar) (*ProxyListener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	pl := &ProxyListener{sc: sc, ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("/egress", pl.handle)
	pl.srv = &http.Server{Handler: mux}
	go func() { _ = pl.srv.Serve(ln) }()
	return pl, nil
}

// Addr is the loopback address local clients dial.
func (p *ProxyListener) Addr() string { return p.ln.Addr().String() }

// Close stops the listener.
func (p *ProxyListener) Close() error { return p.srv.Close() }

func (p *ProxyListener) handle(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	tenant := req.Header.Get(HeaderTenant)
	doc := req.Header.Get(HeaderDoc)
	if tenant == "" || doc == "" {
		http.Error(w, "missing egress identity headers", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := p.sc.Do(req.Context(), Request{
		Tenant:       tenant,
		OriginalName: doc,
		Body:         body,
	})
	if err != nil {
		// Fail closed: map every refusal to 403/502 without a direct-dial hint.
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.Header().Set("X-Egress-Fingerprint", resp.Identity.Fingerprint())
	w.Header().Set("X-Egress-Attempts", itoa(resp.Attempts))
	_, _ = w.Write(resp.Body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
