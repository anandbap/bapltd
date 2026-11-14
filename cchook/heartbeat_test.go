package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookHeartbeatNameIsSafe(t *testing.T) {
	name := hookHeartbeatName("../../etc/passwd")
	if strings.ContainsAny(name, `/\`) {
		t.Fatalf("unsafe heartbeat name %q", name)
	}
}

func TestTouchHookHeartbeatWritesOnlyWhenHooksEnabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAP_STATE_DIR", dir)
	t.Setenv("BAP_HOOKS", "")
	t.Setenv("BAP_DISABLE_HOOKS", "")
	t.Setenv("BAP_MODE", "")

	touchHookHeartbeat("sess-1")
	marker := filepath.Join(dir, "hook-heartbeat", hookHeartbeatName("sess-1"))
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("heartbeat should be written when hooks are enabled: %v", err)
	}

	os.Remove(marker)
	t.Setenv("BAP_DISABLE_HOOKS", "1")
	touchHookHeartbeat("sess-1")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a disabled hook must not write a heartbeat")
	}
}
