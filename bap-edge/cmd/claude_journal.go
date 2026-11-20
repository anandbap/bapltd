package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The process receives its enforcement configuration inline. This journal is
// optional bookkeeping, so transient storage faults cannot stop a governed
// agent. Failed journal writes repair themselves with bounded backoff.
type claudeLaunchJournal struct {
	mu        sync.Mutex
	workspace string
	data      []byte
	owner     claudeOwner
	dir       string
	lastError string
	closed    bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func newClaudeLaunchJournal(workspace, session string, data []byte) *claudeLaunchJournal {
	ctx, cancel := context.WithCancel(context.Background())
	j := &claudeLaunchJournal{workspace: workspace, data: append([]byte(nil), data...), cancel: cancel,
		owner: claudeOwner{Version: 1, Workspace: workspace, Session: session, PID: os.Getpid(), Birth: processBirth(os.Getpid()), Fingerprint: claudeFingerprint(data), State: "prepared"}}
	j.repair()
	j.wg.Add(1)
	go func() {
		defer j.wg.Done()
		for delay := time.Second; ; delay = min(delay*2, 30*time.Second) {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				j.repair()
			}
		}
	}()
	return j
}

func (j *claudeLaunchJournal) repair() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	err := j.repairLocked()
	if err != nil {
		if j.lastError == "" {
			fmt.Fprintf(os.Stderr, "BAP Claude: journal temporarily unavailable (%v); governed startup continues with inline settings. Repair will retry automatically.\n", err)
		}
		j.lastError = err.Error()
	} else if j.lastError != "" {
		fmt.Fprintln(os.Stderr, "BAP Claude: workspace journal recovered automatically.")
		j.lastError = ""
	}
}

func sameClaudeOwner(a, b claudeOwner) bool {
	return a.Version == b.Version && a.Workspace == b.Workspace && a.Session == b.Session && a.PID == b.PID && a.Birth == b.Birth && a.Fingerprint == b.Fingerprint
}

func (j *claudeLaunchJournal) repairLocked() error {
	if j.owner.Birth == "" {
		return fmt.Errorf("process birth identity unavailable; no files claimed")
	}
	root := filepath.Join(j.workspace, ".bap", "claude-launches")
	if err := claudeWorkspacePath(j.workspace, root); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	release, err := acquireClaudeLifecycleLock(j.workspace)
	if err != nil {
		return err
	}
	defer release()
	if j.dir == "" {
		// Unknown leftovers are preserved and diagnosed. They do not own this
		// launch's inline configuration and cannot prevent its startup.
		if err := reconcileClaudeOwners(root, j.workspace); err != nil {
			fmt.Fprintf(os.Stderr, "BAP Claude recovery: %v (preserved; current launch continues).\n", err)
		}
		j.dir, err = os.MkdirTemp(root, "launch-")
		if err != nil {
			return err
		}
	}
	if err := claudeWorkspacePath(j.workspace, j.dir); err != nil {
		return err
	}
	manifest := filepath.Join(j.dir, "owner.json")
	if info, err := os.Lstat(manifest); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("journal manifest redirected; preserving it")
		}
		b, err := os.ReadFile(manifest)
		if err != nil {
			return err
		}
		var existing claudeOwner
		if json.Unmarshal(b, &existing) != nil || !sameClaudeOwner(existing, j.owner) {
			return fmt.Errorf("journal ownership changed; preserving it")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	settings := filepath.Join(j.dir, "settings.json")
	if info, err := os.Lstat(settings); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("journal settings redirected; preserving them")
		}
		b, err := os.ReadFile(settings)
		if err != nil {
			return err
		}
		if claudeFingerprint(b) != j.owner.Fingerprint {
			return fmt.Errorf("journal settings edited; preserving them")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		if err := writeClaudeOwner(j.dir, j.owner); err != nil {
			return err
		}
		f, err := os.OpenFile(settings, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(j.data)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	// Skip rewrites when nothing changed. This keeps healthy sessions quiet and
	// prevents a periodic repair loop from generating unnecessary file traffic.
	if b, err := os.ReadFile(manifest); err == nil {
		var existing claudeOwner
		if json.Unmarshal(b, &existing) == nil && existing == j.owner {
			return nil
		}
	}
	return writeClaudeOwner(j.dir, j.owner)
}

func (j *claudeLaunchJournal) transition(state string, pid int, birth string) {
	j.mu.Lock()
	j.owner.State, j.owner.ChildPID, j.owner.ChildBirth = state, pid, birth
	j.mu.Unlock()
	j.repair()
}

func (j *claudeLaunchJournal) close() {
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return
	}
	j.closed = true
	j.mu.Unlock()
	j.cancel()
	j.wg.Wait()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.dir == "" {
		return
	}
	release, err := acquireClaudeLifecycleLock(j.workspace)
	if err == nil {
		defer release()
		err = cleanupClaudeOwner(j.dir, j.workspace, j.owner)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "BAP Claude recovery: %v; owned artifacts retained for the next automatic startup sweep.\n", err)
	}
}
