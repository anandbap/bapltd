package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

const DefaultExecutionTimeout = 30 * time.Minute
const MaxExecutionTimeout = 24 * time.Hour
const maxCapturedOutput = 4 << 20

type ExecOptions struct {
	Context context.Context
	Timeout time.Duration
	// Progress contains elapsed time only, never unredacted child output.
	Progress func(time.Duration)
}

func executionTimeout(requested time.Duration) (time.Duration, error) {
	if requested == 0 {
		requested = DefaultExecutionTimeout
		if raw := os.Getenv("BAP_EXEC_TIMEOUT_SEC"); raw != "" {
			seconds, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || seconds < 1 || seconds > int64(MaxExecutionTimeout/time.Second) {
				return 0, fmt.Errorf("BAP_EXEC_TIMEOUT_SEC must be between 1 and 86400")
			}
			requested = time.Duration(seconds) * time.Second
		}
	}
	if requested <= 0 || requested > MaxExecutionTimeout {
		return 0, fmt.Errorf("execution timeout must be positive and at most 24h")
	}
	return requested, nil
}

type boundedOutput struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	limit   int
	dropped bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - b.buf.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.dropped = true
	}
	_, _ = b.buf.Write(p)
	return n, nil
}

func (b *boundedOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dropped {
		return b.buf.String() + "\n[BAP: output truncated at 4 MiB]"
	}
	return b.buf.String()
}
