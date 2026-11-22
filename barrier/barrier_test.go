package barrier

import (
	"sync"
	"testing"
	"time"
)

func TestDeterministicRendezvous(t *testing.T) {
	b := New()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b.Arrive("park")
			b.WaitFor("release")
			b.Arrive("done")
		}(i)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && b.ArrivalCount("park") < 3 {
		time.Sleep(time.Millisecond)
	}
	if b.ArrivalCount("park") != 3 || b.IsOpen("release") {
		t.Fatal("goroutines must be parked and the gate closed")
	}
	b.Open("release")
	wg.Wait()
	if b.ArrivalCount("done") != 3 || !b.IsOpen("release") {
		t.Fatal("all goroutines must proceed exactly once after Open")
	}
	// Re-open is idempotent.
	b.Open("release")
}
