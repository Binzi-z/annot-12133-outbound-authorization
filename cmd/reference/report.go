package main

import (
	"fmt"
	"strings"

	"egressz/server"
	"egressz/testsupport"
)

// Report is the result of one scenario.
type Report struct {
	OK       bool
	Evidence []string
	Log      []server.Entry
	Mismatch []testsupport.Mismatch
}

func (r *Report) note(format string, args ...any) {
	r.Evidence = append(r.Evidence, fmt.Sprintf(format, args...))
}

// Print renders the report including the full authoritative receive log.
func (r *Report) Print() {
	for _, e := range r.Evidence {
		fmt.Println("  " + e)
	}
	fmt.Println("  -- server receive-log (authoritative) --")
	if len(r.Log) == 0 {
		fmt.Println("     (no server entries)")
	}
	for _, e := range r.Log {
		hops := len(e.Hops)
		reason := e.Reason
		if reason == "" {
			reason = "-"
		}
		fmt.Printf("     seq=%-2d %-7s proxy=%-13s tenant=%-13s doc=%-13s gen=%d src=%s conn=%s fp=%s hops=%d reason=%s\n",
			e.Seq, e.Decision, e.Proxy, e.Tenant, e.Original, e.Generation,
			e.Source, shortID(e.ConnID), shortID(e.Fingerprint), hops, reason)
	}
	if len(r.Mismatch) == 0 {
		fmt.Println("  RESULT: PASS (sidecar decisions match server receive-log)")
		return
	}
	r.OK = false
	fmt.Println("  RESULT: FAIL")
	for _, m := range r.Mismatch {
		fmt.Printf("     mismatch: %s/%s -> %s\n", m.Tenant, m.Name, m.Detail)
	}
}

func shortID(s string) string {
	if len(s) <= 14 {
		return s
	}
	return s[:14]
}

func joinProxies(names []string) string { return strings.Join(names, ",") }
