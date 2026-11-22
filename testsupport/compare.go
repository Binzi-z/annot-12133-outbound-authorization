package testsupport

import (
	"fmt"
	"strings"

	"egressz/policy"
	"egressz/server"
)

// Expectation is what the sidecar believes should happen for one request.
type Expectation struct {
	Tenant     string
	Original   string
	Decision   policy.Decision
	ReasonSub  string // substring match on the deny reason (empty for allow)
	Hops       int
	ProxyNames []string // proxies expected to log a decision
}

// Mismatch describes one difference between expectation and the receive log.
type Mismatch struct {
	Tenant string
	Name   string
	Detail string
}

// Compare walks the authoritative server receive-log and verifies each
// expectation. An expectation matches when at least one logged entry carries
// the tenant/name, one of the expected proxies, the expected decision, the
// expected hop count and (for denies) the reason substring. It also asserts no
// entry carries the opposite decision for an expected tenant/name pair. A
// sidecar-local block (no server entry) is valid only for an explicit deny.
func Compare(log *server.DecisionLog, wants []Expectation) []Mismatch {
	var mm []Mismatch
	entries := log.Entries()

	for _, w := range wants {
		relevant := filter(entries, w.Tenant, w.Original)
		if len(relevant) == 0 {
			if w.Decision == policy.Deny {
				continue // blocked at the sidecar before any stream
			}
			mm = append(mm, Mismatch{w.Tenant, w.Original,
				"expected server entries but receive-log has none"})
			continue
		}

		matchedProxy := map[string]bool{}
		for _, e := range relevant {
			// Opposite decision anywhere for this pair is a hard failure.
			if e.Decision != w.Decision {
				mm = append(mm, Mismatch{w.Tenant, w.Original, fmt.Sprintf(
					"proxy %s logged %s, want %s (reason=%q)",
					e.Proxy, e.Decision, w.Decision, e.Reason)})
				continue
			}
			if w.Decision == policy.Deny && w.ReasonSub != "" &&
				!strings.Contains(e.Reason, w.ReasonSub) {
				mm = append(mm, Mismatch{w.Tenant, w.Original, fmt.Sprintf(
					"proxy %s reason %q does not contain %q",
					e.Proxy, e.Reason, w.ReasonSub)})
				continue
			}
			for _, p := range w.ProxyNames {
				if e.Proxy == p && len(e.Hops) == w.Hops {
					matchedProxy[p] = true
				}
			}
		}
		for _, p := range w.ProxyNames {
			if !matchedProxy[p] {
				mm = append(mm, Mismatch{w.Tenant, w.Original, fmt.Sprintf(
					"no %s entry on proxy %s with %d hops", w.Decision, p, w.Hops)})
			}
		}
	}
	return mm
}

func filter(entries []server.Entry, tenant, original string) []server.Entry {
	var out []server.Entry
	for _, e := range entries {
		if e.Tenant == tenant && e.Original == original {
			out = append(out, e)
		}
	}
	return out
}

// AssertNoAllowFor returns mismatches if any ALLOW entry exists for a key.
func AssertNoAllowFor(log *server.DecisionLog, tenant, original string) []Mismatch {
	var mm []Mismatch
	for _, e := range log.Entries() {
		if e.Tenant == tenant && e.Original == original && e.Decision == policy.Allow {
			mm = append(mm, Mismatch{tenant, original, fmt.Sprintf(
				"unexpected ALLOW on proxy %s conn %s", e.Proxy, e.ConnID)})
		}
	}
	return mm
}
