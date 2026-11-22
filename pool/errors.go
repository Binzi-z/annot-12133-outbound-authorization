package pool

import (
	"errors"
	"time"
)

// ErrPoolExhausted means the per-identity session cap was reached.
var ErrPoolExhausted = errors.New("pool: session cap reached for identity bucket")

func nowUnixNano() int64 { return time.Now().UnixNano() }
