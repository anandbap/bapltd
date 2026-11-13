package config

import (
	"errors"
	"fmt"
	"io"
	"time"

	"bap-edge/internal/policystore"
)

// WaitForTrustedPolicy is the start-up gate for long-running bapedge processes. If the cached
// signed rules are tampered with (or deleted) and the control plane is down, the process does
// not start: it waits and retries until the control plane is reachable and has re-issued
// freshly signed rules. Any other outcome (success, or a different error) is returned at once.
//
// poll<=0 uses 5s. maxWait<=0 waits indefinitely; callers that must not hang (CI, one-shot
// commands) pass a bound or call BootstrapControlPlane directly and fail closed.
func WaitForTrustedPolicy(serverOverride string, poll, maxWait time.Duration, out io.Writer) (BootstrapResult, error) {
	if poll <= 0 {
		poll = 5 * time.Second
	}
	deadline := time.Time{}
	if maxWait > 0 {
		deadline = time.Now().Add(maxWait)
	}
	warned := false
	for {
		res, err := BootstrapControlPlane(serverOverride)
		if err == nil || !errors.Is(err, policystore.ErrPolicyTampered) {
			if warned && err == nil && out != nil {
				fmt.Fprintln(out, "[BAP] Control plane reachable; signed rules re-issued and verified. Starting.")
			}
			return res, err
		}
		if !warned && out != nil {
			fmt.Fprintln(out, "[BAP ZERO-TRUST] Cached policy failed integrity verification and the control plane is unreachable.")
			fmt.Fprintln(out, "[BAP ZERO-TRUST] FAIL-CLOSED: waiting for the control plane to reconnect and re-issue signed rules...")
			warned = true
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return res, err
		}
		time.Sleep(poll)
	}
}
