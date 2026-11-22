package pool

import "net"

// loopbackClient returns a client-side net.Conn connected to a throwaway
// loopback listener whose accept goroutine simply drains and holds the
// connection. This keeps the mux client handshake (a blocking write) alive
// without involving net.Pipe's unbuffered rendezvous.
func loopbackClient(t interface{ Fatal(...any) }) net.Conn {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			buf := make([]byte, 256)
			for {
				if _, err := conn.Read(buf); err != nil {
					conn.Close()
					return
				}
			}
		}()
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
