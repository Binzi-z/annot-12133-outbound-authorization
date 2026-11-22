package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"
)

// StoredDoc is one versioned document held by the loopback origin.
type StoredDoc struct {
	Tenant  string `json:"tenant"`
	Name    string `json:"name"`
	Version int    `json:"version"`
	Body    string `json:"body"`
}

// Origin is a loopback TCP service speaking length-prefixed JSON documents.
// It records every byte received so tests can assert exactly which identity's
// traffic actually reached the origin.
type Origin struct {
	ln       net.Listener
	mu       sync.Mutex
	docs     map[string]StoredDoc // key tenant/name
	received [][]byte
	closed   bool
	delay    time.Duration
}

// SetDelay makes every request block for d before responding, used to create a
// deterministic window for revocation/lease races.
func (o *Origin) SetDelay(d time.Duration) {
	o.mu.Lock()
	o.delay = d
	o.mu.Unlock()
}

func (o *Origin) currentDelay() time.Duration {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.delay
}

// NewOrigin starts a loopback origin and returns it with its address.
func NewOrigin() (*Origin, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	o := &Origin{ln: ln, docs: map[string]StoredDoc{}}
	go o.serve()
	return o, nil
}

// Addr is the origin's loopback address.
func (o *Origin) Addr() string { return o.ln.Addr().String() }

// Close stops the origin.
func (o *Origin) Close() error {
	o.mu.Lock()
	o.closed = true
	o.mu.Unlock()
	return o.ln.Close()
}

// Received returns a copy of every raw request body that arrived.
func (o *Origin) Received() [][]byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([][]byte, len(o.received))
	for i, b := range o.received {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

// Docs returns the stored document map.
func (o *Origin) Docs() map[string]StoredDoc {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[string]StoredDoc, len(o.docs))
	for k, v := range o.docs {
		out[k] = v
	}
	return out
}

func (o *Origin) serve() {
	for {
		conn, err := o.ln.Accept()
		if err != nil {
			return
		}
		go o.handle(conn)
	}
}

func (o *Origin) handle(conn net.Conn) {
	defer conn.Close()
	raw, err := io.ReadAll(conn)
	if err != nil || len(raw) == 0 {
		return
	}
	if d := o.currentDelay(); d > 0 {
		time.Sleep(d)
	}
	o.mu.Lock()
	o.received = append(o.received, append([]byte(nil), raw...))
	var doc StoredDoc
	if jerr := json.Unmarshal(raw, &doc); jerr == nil && doc.Tenant != "" && doc.Name != "" {
		key := doc.Tenant + "/" + doc.Name
		cur := o.docs[key]
		doc.Version = cur.Version + 1
		o.docs[key] = doc
	}
	o.mu.Unlock()

	resp := map[string]any{"status": "stored", "bytes": len(raw)}
	body, _ := json.Marshal(resp)
	_, _ = conn.Write(append(body, '\n'))
}

// EncodeDoc builds the wire body for one document PUT.
func EncodeDoc(tenant, name, body string) []byte {
	b, _ := json.Marshal(StoredDoc{Tenant: tenant, Name: name, Body: body})
	return b
}

// DecodeResponse parses an origin response.
func DecodeResponse(b []byte) (map[string]any, error) {
	var m map[string]any
	err := json.NewDecoder(bytes.NewReader(b)).Decode(&m)
	return m, err
}
