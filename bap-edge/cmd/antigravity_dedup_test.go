package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bap-edge/internal/state"
)

func TestAntigravitySessionDeduplication_AdoptsExistingSession(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("BAP_STATE_DIR", tmpDir)
	state.ResetForTesting()

	sessDir := state.SessionsDir()
	sessID := "sess-antigravity-canonical-999"
	pid := os.Getpid()

	marker := map[string]any{
		"session_id":      sessID,
		"app_id":          "antigravity",
		"pid":             pid,
		"started_at":      time.Now().UTC(),
		"reporting_layer": "plugin",
	}
	data, err := json.Marshal(marker)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	markerPath := filepath.Join(sessDir, sessID+".json")
	if err := os.WriteFile(markerPath, data, 0600); err != nil {
		t.Fatalf("write marker error: %v", err)
	}
	pidMarkerPath := filepath.Join(sessDir, filepath.Base(sessionPIDMarkerPath(pid)))
	if err := os.WriteFile(pidMarkerPath, data, 0600); err != nil {
		t.Fatalf("write pid marker error: %v", err)
	}

	// 1. Verify findActiveNativeSession finds this canonical session
	found := findActiveNativeSession("antigravity", pid)
	if found != sessID {
		t.Errorf("expected findActiveNativeSession to find %q, got %q", sessID, found)
	}

	// 2. Verify resolvePluginSessionID reuses the canonical session instead of minting a new one
	t.Setenv("BAP_SESSION_ID", "")
	pluginSess := resolvePluginSessionID("antigravity", map[string]any{})
	if pluginSess != sessID {
		t.Errorf("expected resolvePluginSessionID to adopt %q, got %q", sessID, pluginSess)
	}

	// 3. Verify ensureMCPSession reuses the canonical session instead of minting a new one
	clearDevEnv(t)
	t.Setenv("LTD_SOURCE", "antigravity")
	mcpSess := ensureMCPSession("", "http://127.0.0.1:59999")
	if mcpSess != sessID {
		t.Errorf("expected ensureMCPSession to adopt %q, got %q", sessID, mcpSess)
	}
}

func TestAntigravityPromptTail_HashDeduplicationAndLock(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("BAP_STATE_DIR", tmpDir)
	state.ResetForTesting()

	pHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	if isPromptHashSent(pHash) {
		t.Fatalf("expected hash to be unsent initially")
	}

	markPromptHashSent(pHash)

	if !isPromptHashSent(pHash) {
		t.Fatalf("expected hash to be marked as sent")
	}

	// Test prompt tail lock
	if isPromptTailerRunningElsewhere() {
		t.Fatalf("expected prompt tailer to not be running elsewhere initially")
	}

	updatePromptTailLock("sess-test-lock")

	// Since current process owns the lock, isPromptTailerRunningElsewhere should be false for ourselves
	if isPromptTailerRunningElsewhere() {
		t.Fatalf("isPromptTailerRunningElsewhere should be false for own PID")
	}

	releasePromptTailLock()
	if _, err := os.Stat(promptTailLockPath()); !os.IsNotExist(err) {
		t.Fatalf("expected lock file to be removed after release")
	}
}
