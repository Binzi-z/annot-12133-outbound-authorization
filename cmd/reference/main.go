// Command reference is the executable reference model for the local egress
// authorization sidecar. It stands up an entirely loopback topology (policy
// service, origin, edge and redirect mux proxies, sidecar, document sync
// client) and enumerates the interleavings of connection establishment,
// borrowing, redirects, revocation and response arrival for two tenants.
//
// Every scenario prints the sidecar's expectation, the authoritative server
// receive-log entries, a PASS/FAIL comparison, and pool/identity evidence.
// Nothing in this command accesses the public network.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"egressz/sidecar"
	"egressz/testsupport"
)

func main() {
	failFast := flag.Bool("fail-fast", false, "stop at the first failing scenario")
	flag.Parse()

	ctx := context.Background()
	pass, fail := runAll(ctx, *failFast)
	fmt.Printf("\n================ SUMMARY ================\n")
	fmt.Printf("scenarios passed: %d, failed: %d\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func runAll(ctx context.Context, failFast bool) (int, int) {
	scenarios := buildScenarios()
	pass, fail := 0, 0
	for _, sc := range scenarios {
		fmt.Printf("\n########## SCENARIO %d: %s ##########\n", sc.ID, sc.Title)
		report := sc.Run(ctx)
		report.Print()
		if report.OK {
			pass++
		} else {
			fail++
			if failFast {
				break
			}
		}
	}
	return pass, fail
}

// env builds a fresh topology for one scenario.
func env(ctx context.Context, mode sidecar.RevokeMode, lease time.Duration, retries int) (*testsupport.Topology, error) {
	return testsupport.Standup(ctx, testsupport.Config{
		RevokeMode: mode,
		Lease:      lease,
		MaxRetries: retries,
		MaxPerKey:  4,
		Initial:    testsupport.InitialSnapshot(),
	})
}
