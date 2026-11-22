// Package client is the document synchronization test client. It produces
// idempotent document PUTs and drives them through the local sidecar; it never
// dials the network itself, so all egress identity and trust is established by
// the sidecar.
package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"egressz/server"
	"egressz/sidecar"
)

// Document is a locally edited document awaiting synchronization.
type Document struct {
	Tenant string
	Name   string
	Body   string
	// Rev is the idempotency key. Re-sending the same Rev must not create a
	// duplicate origin version.
	Rev int
}

// Outcome records what happened to one sync attempt.
type Outcome struct {
	Doc       Document
	OK        bool
	Attempts  int
	Redirects int
	Nonce     string
	Error     string
	At        time.Time
}

// SyncClient synchronizes documents through a sidecar.
type SyncClient struct {
	sc   *sidecar.Sidecar
	mu   sync.Mutex
	seen map[string]int64 // nonce -> first observed, for idempotency tracking
}

// New builds a sync client bound to a sidecar.
func New(sc *sidecar.Sidecar) *SyncClient {
	return &SyncClient{sc: sc, seen: map[string]int64{}}
}

// SyncOne sends one document and records the outcome.
func (c *SyncClient) SyncOne(ctx context.Context, doc Document) Outcome {
	body := server.EncodeDoc(doc.Tenant, doc.Name, doc.Body)
	req := sidecar.Request{
		Tenant:       doc.Tenant,
		OriginalName: doc.Name,
		Body:         body,
	}
	out := Outcome{Doc: doc, At: time.Now().UTC()}
	resp, err := c.sc.Do(ctx, req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	c.mu.Lock()
	c.seen[resp.Nonce] = time.Now().UnixNano()
	c.mu.Unlock()
	out.OK = true
	out.Attempts = resp.Attempts
	out.Redirects = resp.Redirected
	out.Nonce = resp.Nonce
	return out
}

// SyncMany runs several documents concurrently with a worker count and returns
// outcomes in completion order. Used to interleave two tenants deterministically
// (the harness controls scheduling via the sidecar barrier hooks).
func (c *SyncClient) SyncMany(ctx context.Context, docs []Document, workers int) []Outcome {
	if workers <= 0 {
		workers = 1
	}
	jobs := make(chan Document)
	results := make(chan Outcome, len(docs))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for doc := range jobs {
				results <- c.SyncOne(ctx, doc)
			}
		}()
	}
	for _, d := range docs {
		jobs <- d
	}
	close(jobs)
	wg.Wait()
	close(results)
	out := make([]Outcome, 0, len(docs))
	for r := range results {
		out = append(out, r)
	}
	return out
}

// String gives a compact one-line description for the scenario report.
func (o Outcome) String() string {
	if o.OK {
		return fmt.Sprintf("OK   %s/%s rev=%d attempts=%d redirects=%d nonce=%s",
			o.Doc.Tenant, o.Doc.Name, o.Doc.Rev, o.Attempts, o.Redirects, short(o.Nonce))
	}
	return fmt.Sprintf("FAIL %s/%s rev=%d err=%s", o.Doc.Tenant, o.Doc.Name, o.Doc.Rev, o.Error)
}

// Err returns the recorded error as an error interface (nil when OK).
func (o Outcome) Err() error {
	if o.Error == "" {
		return nil
	}
	return outcomeError(o.Error)
}

type outcomeError string

func (e outcomeError) Error() string { return string(e) }

func short(s string) string {
	if len(s) <= 10 {
		return s
	}
	return s[:10]
}
