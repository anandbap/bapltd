package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A crashed writer's stale lock file must not block the audit trail forever.
func TestAcquireLogLockBreaksStaleLock(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	lock := logPath + ".lock"
	if err := os.WriteFile(lock, []byte("999999"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	release := acquireLogLock(logPath)
	if _, err := os.Stat(lock); err != nil {
		t.Fatal("expected a fresh lock to be held after breaking the stale one")
	}
	release()
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("lock file must be removed on release")
	}
}

// A second writer (another process) must wait for a live lock instead of reading a stale tail.
func TestAcquireLogLockSerializesWriters(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	release1 := acquireLogLock(logPath)

	got := make(chan struct{})
	go func() {
		release2 := acquireLogLock(logPath)
		close(got)
		release2()
	}()

	select {
	case <-got:
		t.Fatal("second writer acquired the lock while the first still held it")
	case <-time.After(150 * time.Millisecond):
	}
	release1()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("second writer never acquired the lock after release")
	}
}

// End to end: many sequential appends under the lock keep the chain verifiable.
func TestLogChainStaysValidWithLock(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 25; i++ {
		if err := Log(AuditEntry{Source: "test", Executable: "git", FullCommand: "git status", Decision: "allow"}, logPath); err != nil {
			t.Fatal(err)
		}
	}
	ok, n, err := VerifyLocalLog(logPath)
	if !ok || err != nil || n != 25 {
		t.Fatalf("chain invalid: ok=%v n=%d err=%v", ok, n, err)
	}
	if _, err := os.Stat(logPath + ".lock"); !os.IsNotExist(err) {
		t.Fatal("lock file leaked after Log")
	}
}
