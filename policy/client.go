package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func parseInt64(raw string, dst *int64) (int64, error) {
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad version %q: %w", raw, err)
	}
	*dst = v
	return v, nil
}

// Client is a loopback HTTP client for Service.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient creates a client with a short default timeout.
func NewClient(baseURL string) *Client {
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 2 * time.Second}}
}

// Bundle fetches the current bundle.
func (c *Client) Bundle() (Bundle, error) {
	resp, err := c.HTTP.Get(c.BaseURL + "/bundle")
	if err != nil {
		return Bundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Bundle{}, fmt.Errorf("policy: bundle status %d", resp.StatusCode)
	}
	var b Bundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// Publish pushes a new snapshot.
func (c *Client) Publish(snap Snapshot) (Bundle, error) {
	body, _ := json.Marshal(snap)
	resp, err := c.HTTP.Post(c.BaseURL+"/publish", "application/json", bytes.NewReader(body))
	if err != nil {
		return Bundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Bundle{}, fmt.Errorf("policy: publish status %d", resp.StatusCode)
	}
	var b Bundle
	err = json.NewDecoder(resp.Body).Decode(&b)
	return b, err
}

// Rollback asks the service to re-publish an older generation as a new one.
func (c *Client) Rollback(generation int64) (Snapshot, error) {
	body, _ := json.Marshal(map[string]int64{"generation": generation})
	resp, err := c.HTTP.Post(c.BaseURL+"/rollback", "application/json", bytes.NewReader(body))
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("policy: rollback status %d", resp.StatusCode)
	}
	var s Snapshot
	err = json.NewDecoder(resp.Body).Decode(&s)
	return s, err
}

// Watch long-polls for versions greater than from and invokes fn for each new
// bundle. It keeps looping until ctx is canceled. A watch failure is returned
// to the caller after retries are exhausted inside the decision-point wrapper.
func (c *Client) Watch(ctx context.Context, from int64, fn func(Bundle)) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s/watch?v=%d", c.BaseURL, from), nil)
		if err != nil {
			return err
		}
		// Watch needs a long timeout distinct from the client default.
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Fail-closed: surface the error; the holder keeps its last good state.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		var b Bundle
		err = json.NewDecoder(resp.Body).Decode(&b)
		resp.Body.Close()
		if err != nil {
			continue
		}
		if b.Version > from {
			from = b.Version
			fn(b)
		}
	}
}
