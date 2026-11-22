package main

import (
	"context"
	"testing"
)

// TestAllScenarios exercises every enumerated interleaving through the public
// scenario entry points and fails if any scenario does not reconcile with the
// authoritative server receive-log. This makes the reference model executable
// via `go test ./...` in sandboxes that forbid an extra output binary.
func TestAllScenarios(t *testing.T) {
	ctx := context.Background()
	for _, sc := range buildScenarios() {
		t.Run(sc.Title, func(t *testing.T) {
			report := sc.Run(ctx)
			if !report.OK {
				for _, ev := range report.Evidence {
					t.Logf("  %s", ev)
				}
				for _, m := range report.Mismatch {
					t.Errorf("%s/%s: %s", m.Tenant, m.Name, m.Detail)
				}
				if len(report.Mismatch) == 0 {
					t.Errorf("scenario %d failed without explicit mismatches", sc.ID)
				}
			}
		})
	}
}

// TestRunAllReportsZeroFailures drives the same top-level entry point the
// command's main() uses and asserts every scenario reconciles.
func TestRunAllReportsZeroFailures(t *testing.T) {
	pass, fail := runAll(context.Background(), false)
	if fail != 0 || pass != len(buildScenarios()) {
		t.Fatalf("want %d pass / 0 fail, got %d pass / %d fail",
			len(buildScenarios()), pass, fail)
	}
}
