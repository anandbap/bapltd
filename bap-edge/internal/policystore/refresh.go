package policystore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// DefaultSyncInterval is how often a running bapedge polls the control plane. A change an
// admin makes therefore reaches every connected machine within a few seconds.
const DefaultSyncInterval = 3 * time.Second

// DefaultMaxStaleness bounds how old the cached rules may be before a short-lived invocation
// (a hook or `bapedge check`) refreshes them itself.
const DefaultMaxStaleness = 5 * time.Second

// cachedStateVerifies reports whether a cached state is trustworthy. Unmanaged machines (no
// pinned key) have nothing to verify against and are treated as valid.
func (s *Store) cachedStateVerifies(st PolicyState) bool {
	pin, managed := s.LoadPin()
	if !managed {
		return true
	}
	return verifyBundleAgainstPin(pin, s.AssetID(), st.asBundle(), st.Digest) == nil
}

// touchLastSync records that the cache was just confirmed current by the control plane.
// LastSync is deliberately outside the signed payload, so this cannot weaken verification.
func (s *Store) touchLastSync() {
	st, err := s.LoadState()
	if err != nil {
		return
	}
	st.LastSync = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	tmp := filepath.Join(s.directory, "policy-state.json.tmp")
	if os.WriteFile(tmp, data, 0600) == nil {
		_ = os.Rename(tmp, filepath.Join(s.directory, "policy-state.json"))
	}
}

// RefreshIfStale syncs with the control plane when the cache is older than maxAge. Failures
// are ignored on purpose: while the control plane is unreachable the last signed rules stay in
// force (and tampering is caught by Current(), not here).
func (s *Store) RefreshIfStale(serverURL string, maxAge, timeout time.Duration) {
	if serverURL == "" {
		return
	}
	if st, err := s.LoadState(); err == nil && time.Since(st.LastSync) < maxAge && s.cachedStateVerifies(st) {
		return
	}
	_, _, _ = s.SyncWithServer(serverURL, "", timeout)
}

// RunSyncLoop keeps a long-running process (bapedge watch / start) in step with the control
// plane until ctx is cancelled.
func (s *Store) RunSyncLoop(ctx context.Context, serverURL string, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultSyncInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		_, _, _ = s.SyncWithServer(serverURL, "", 2*time.Second)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
