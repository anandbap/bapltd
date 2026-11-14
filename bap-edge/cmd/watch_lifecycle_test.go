package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func isolateUserDir(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestOnlyOneWatcherPerSession(t *testing.T) {
	isolateUserDir(t)
	release, ok := acquireWatcherLock("sess-1")
	if !ok {
		t.Fatal("first watcher must get the lock")
	}
	// A second watcher for the same session (this process is the live owner) must stand down.
	// Simulate another process by recording a different, live PID as the owner.
	lock := filepath.Join(bapUserDir(), "watchers", sanitizeInstanceID("sess-1")+".lock")
	if err := os.WriteFile(lock, []byte(strconv.Itoa(os.Getppid())), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok2 := acquireWatcherLock("sess-1"); ok2 {
		t.Fatal("a duplicate watcher for the same session must not start")
	}
	// A different session is independent.
	if rel3, ok3 := acquireWatcherLock("sess-2"); !ok3 {
		t.Fatal("another session must get its own watcher")
	} else {
		rel3()
	}
	_ = os.Remove(lock)
	release() // not the owner any more: must not remove someone else's lock
	if _, ok4 := acquireWatcherLock("sess-1"); !ok4 {
		t.Fatal("after the owner is gone the lock must be available")
	}
}

func TestDeadOrStaleWatcherLockIsTakenOver(t *testing.T) {
	isolateUserDir(t)
	lock := filepath.Join(bapUserDir(), "watchers", sanitizeInstanceID("sess-x")+".lock")
	_ = os.MkdirAll(filepath.Dir(lock), 0700)

	// Owner PID that does not exist.
	_ = os.WriteFile(lock, []byte("2147483646"), 0600)
	if _, ok := acquireWatcherLock("sess-x"); !ok {
		t.Fatal("a lock held by a dead process must be taken over")
	}
	_ = os.Remove(lock)

	// Live PID but untouched for longer than the stale window (crash / PID reuse).
	_ = os.WriteFile(lock, []byte(strconv.Itoa(os.Getppid())), 0600)
	old := time.Now().Add(-2 * watcherLockStale)
	_ = os.Chtimes(lock, old, old)
	if _, ok := acquireWatcherLock("sess-x"); !ok {
		t.Fatal("a stale lock must be taken over even if its PID looks alive")
	}
}

func TestWatcherStopsWhenSessionMarkerIsRemoved(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "session.json")
	misses := 0
	if sessionMarkerGone(marker, &misses) {
		t.Fatal("one transient miss must not stop the watcher")
	}
	_ = os.WriteFile(marker, []byte("{}"), 0600)
	if sessionMarkerGone(marker, &misses) || misses != 0 {
		t.Fatal("marker present: counter must reset")
	}
	_ = os.Remove(marker)
	sessionMarkerGone(marker, &misses)
	if !sessionMarkerGone(marker, &misses) {
		t.Fatal("two consecutive misses (session ended or swept) must stop the watcher")
	}
}
