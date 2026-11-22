package mux

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"egressz/authz"
)

// newPair stands up a real loopback TCP listener so the client hello and server
// handshake run on separate goroutines (net.Pipe would deadlock the
// unbuffered synchronous write). Everything remains on 127.0.0.1.
func newPair(t *testing.T, secret []byte, verifier Verifier, logger DecisionLogger) (*Session, *Session) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	type serverResult struct {
		sess *Session
		err  error
	}
	srvCh := make(chan serverResult, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			srvCh <- serverResult{err: aerr}
			return
		}
		sess, serr := Server(conn, secret, verifier, logger)
		srvCh <- serverResult{sess: sess, err: serr}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientSess, err := Dial(conn, "conn-x")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	res := <-srvCh
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = clientSess.Close()
		_ = res.sess.Close()
	})
	return clientSess, res.sess
}

func TestStreamRoundTripAndConnBinding(t *testing.T) {
	secret := []byte("secret")
	var gotID authz.Identity
	var wg sync.WaitGroup
	wg.Add(1)
	client, server := newPair(t, secret, func(id authz.Identity) error {
		gotID = id
		wg.Done()
		return nil
	}, nil)

	st, err := client.Open()
	if err != nil {
		t.Fatal(err)
	}
	id := authz.Identity{Tenant: "t", OriginalName: "d", ConnID: "conn-x"}
	if err := st.SendAuth(authz.MintToken(secret, id, "n")); err != nil {
		t.Fatal(err)
	}

	srvStream, srvID, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if srvID.ConnID != "conn-x" {
		t.Fatalf("server identity conn mismatch: %s", srvID.ConnID)
	}
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()
	body, err := readAll(srvStream)
	if err != nil || string(body) != "hello" {
		t.Fatalf("server read %q err=%v", body, err)
	}
	if _, err := srvStream.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	_ = srvStream.CloseWrite()
	reply, err := readAll(st)
	if err != nil || string(reply) != "world" {
		t.Fatalf("client read %q err=%v", reply, err)
	}
	wg.Wait()
	if gotID.ConnID != "conn-x" {
		t.Fatal("verifier did not see the bound identity")
	}
}

func TestRejectMismatchedConnID(t *testing.T) {
	secret := []byte("secret")
	denied := make(chan string, 1)
	client, _ := newPair(t, secret, nil, func(_ authz.Identity, allowed bool, reason string) {
		if !allowed {
			denied <- reason
		}
	})

	st, _ := client.Open()
	id := authz.Identity{Tenant: "t", OriginalName: "d", ConnID: "conn-FORGED"}
	_ = st.SendAuth(authz.MintToken(secret, id, "n"))

	select {
	case reason := <-denied:
		if reason == "" || !contains(reason, "conn_id_mismatch") {
			t.Fatalf("want conn_id_mismatch, got %q", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("denial was not logged")
	}

	if _, err := st.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = st.CloseWrite()
	if _, err := readAll(st); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("want stream reset, got %v", err)
	}
}

func TestRejectBadMAC(t *testing.T) {
	secret := []byte("secret")
	denied := make(chan string, 1)
	client, _ := newPair(t, secret, nil, func(_ authz.Identity, allowed bool, reason string) {
		if !allowed {
			denied <- reason
		}
	})

	st, _ := client.Open()
	tok := authz.MintToken([]byte("wrong-secret"),
		authz.Identity{Tenant: "t", OriginalName: "d", ConnID: "conn-x"}, "n")
	_ = st.SendAuth(tok)
	select {
	case reason := <-denied:
		if reason == "" {
			t.Fatal("expected denial reason for bad MAC")
		}
	case <-time.After(time.Second):
		t.Fatal("bad-MAC denial not observed")
	}
}

func TestSessionCloseUnblocksStreams(t *testing.T) {
	client, _ := newPair(t, []byte("s"), nil, nil)
	st, err := client.Open()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = client.Close()
	}()
	if _, err := readAll(st); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("want session closed error, got %v", err)
	}
}

func readAll(st *Stream) ([]byte, error) {
	var out []byte
	buf := make([]byte, 64)
	for {
		n, err := st.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
