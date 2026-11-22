package sidecar

import (
	"net"
	"strings"
)

// GuardedDialer wraps the only permitted net.Dial path. It enforces that every
// dial targets an explicitly allowed loopback address. There is intentionally
// no fallback that dials an "origin directly": if no authorized proxy address
// is available, every dial fails with ErrDirectDialBlocked. This is what makes
// "system failure must not silently fall back to direct connection" a property
// of the code rather than of configuration.
type GuardedDialer struct {
	allowed map[string]bool
}

// NewGuardedDialer builds a dialer from allowed host:port addresses.
func NewGuardedDialer(addresses ...string) *GuardedDialer {
	g := &GuardedDialer{allowed: map[string]bool{}}
	for _, a := range addresses {
		g.allowed[a] = true
	}
	return g
}

// Allow adds an address at runtime (e.g. when a new redirect proxy starts).
func (g *GuardedDialer) Allow(address string) { g.allowed[address] = true }

// Allowed reports whether address may be dialed.
func (g *GuardedDialer) Allowed(address string) bool { return g.allowed[address] }

// Dial opens a TCP connection, but only to an allow-listed loopback address.
func (g *GuardedDialer) Dial(network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: ErrDirectDialBlocked}
	}
	// The loopback check runs first so a public address can never be rescued
	// by appearing in the (loopback-only) allowlist.
	host, _, err := net.SplitHostPort(address)
	if err != nil || !isLoopback(host) {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: addr(address),
			Err: ErrNonLoopback(address)}
	}
	if !g.allowed[address] {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: addr(address),
			Err: ErrDirectDialedGuard(address)}
	}
	return net.Dial(network, address)
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

type addrString string

func (a addrString) Network() string { return "tcp" }
func (a addrString) String() string  { return string(a) }

func addr(s string) net.Addr { return addrString(s) }
