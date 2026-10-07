package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunSetup(t *testing.T) {
	tempDir := t.TempDir()

	err := RunSetup([]string{"--dir", tempDir, "--app", "claude-code"})
	if err != nil {
		t.Fatalf("RunSetup failed: %v", err)
	}

	// Verify .claude/managed-settings.json
	managedSettingsPath := filepath.Join(tempDir, ".claude", "managed-settings.json")
	data, err := os.ReadFile(managedSettingsPath)
	if err != nil {
		t.Fatalf("failed to read managed-settings.json: %v", err)
	}

	var settings struct {
		DangerouslySkipPermissions bool `json:"dangerouslySkipPermissions"`
		BAPManaged                 bool `json:"bap_managed"`
		LifecycleHooks             struct {
			PreToolUse string `json:"pre_tool_use"`
		} `json:"lifecycle_hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("failed to unmarshal managed-settings: %v", err)
	}

	if settings.DangerouslySkipPermissions {
		t.Errorf("expected dangerouslySkipPermissions to be false, got true")
	}
	if !settings.BAPManaged {
		t.Errorf("expected bap_managed to be true")
	}
	if settings.LifecycleHooks.PreToolUse != "bapedge exec" {
		t.Errorf("expected pre_tool_use hook to be 'bapedge exec', got %s", settings.LifecycleHooks.PreToolUse)
	}

	// Verify .bap/config.json
	bapCfgPath := filepath.Join(tempDir, ".bap", "config.json")
	if _, err := os.Stat(bapCfgPath); err != nil {
		t.Fatalf("expected .bap/config.json to exist, got %v", err)
	}

	// Verify idempotency
	if err := RunSetup([]string{"--dir", tempDir}); err != nil {
		t.Fatalf("subsequent RunSetup failed: %v", err)
	}
}

func TestRunStatus(t *testing.T) {
	err := RunStatus([]string{})
	if err != nil {
		t.Fatalf("RunStatus failed: %v", err)
	}
}

func TestRunWhy(t *testing.T) {
	// Test empty args prints usage
	if err := RunWhy([]string{}); err != nil {
		t.Fatalf("RunWhy empty args failed: %v", err)
	}

	// Test benign git command
	if err := RunWhy([]string{"git", "status"}); err != nil {
		t.Fatalf("RunWhy git status failed: %v", err)
	}

	// Test destructive command
	if err := RunWhy([]string{"rm", "-rf", "/"}); err != nil {
		t.Fatalf("RunWhy rm -rf failed: %v", err)
	}
}

func TestRunSweepLocal(t *testing.T) {
	// Create temporary dummy session in .bap/sessions with dead PID
	sessionsDir := filepath.Join(".bap", "sessions")
	_ = os.MkdirAll(sessionsDir, 0700)

	dummySessionID := "sess-test-sweep-dummy-9999"
	deadPID := 99999999
	markerPath := filepath.Join(sessionsDir, "test-sweep-dummy.json")

	marker := map[string]any{
		"session_id": dummySessionID,
		"pid":        deadPID,
		"started_at": time.Now().Add(-10 * time.Minute),
	}
	markerData, _ := json.Marshal(marker)
	_ = os.WriteFile(markerPath, markerData, 0600)

	// Run sweep
	err := RunSweep([]string{"--server", "http://127.0.0.1:9999"})
	if err != nil {
		t.Fatalf("RunSweep failed: %v", err)
	}

	// Verify dead marker was cleaned up
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Errorf("expected dead marker %s to be swept and deleted", markerPath)
	}
}

func TestCheckOtherBapEdgeInstances(t *testing.T) {
	status := CheckOtherBapEdgeInstances()
	// In the test process itself without a background daemon running,
	// OtherRunning should typically be false, or if another test process is running,
	// description should be populated.
	if status.Description == "" {
		t.Errorf("expected description to be non-empty")
	}
}

func TestPerformSweep(t *testing.T) {
	res, err := PerformSweep("http://127.0.0.1:9999", false)
	if err != nil {
		t.Fatalf("PerformSweep failed: %v", err)
	}
	_ = res
}
