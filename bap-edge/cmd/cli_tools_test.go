package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/state"
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

func TestRunStatus_EnrolledDiscovery(t *testing.T) {
	tmpDir := t.TempDir()
	credsPath := filepath.Join(tmpDir, "credentials.json")
	creds := StoredCredentials{
		ServerURL:    "http://127.0.0.1:54321",
		AgentID:      "agent-test-status-enrolled",
		AppID:        "claude-code-workstation",
		InstanceID:   "inst-status-01",
		SessionToken: "mock-session-token",
		AuthMode:     "oidc",
		UserEmail:    "status-test@corp.internal",
		Department:   "Engineering",
		IdPProvider:  "google",
		EnrolledAt:   time.Now(),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	if err := os.WriteFile(credsPath, data, 0600); err != nil {
		t.Fatalf("failed to write test creds: %v", err)
	}

	origEnv := os.Getenv("BAP_CREDENTIALS")
	os.Setenv("BAP_CREDENTIALS", credsPath)
	defer os.Setenv("BAP_CREDENTIALS", origEnv)

	err := RunStatus([]string{"--json", "--no-sweep"})
	if err != nil {
		t.Fatalf("RunStatus with enrolled credentials failed: %v", err)
	}
}

func TestRunStatus_OTCEnrolledDoesNotPurgeCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	credsPath := filepath.Join(tmpDir, "credentials.json")
	creds := StoredCredentials{
		ServerURL:    "http://127.0.0.1:54321",
		AgentID:      "agent-test-otc-enrolled",
		AppID:        "claude-code",
		InstanceID:   "inst-otc-01",
		SessionToken: "mock-session-token",
		AuthMode:     "otc",
		EnrolledAt:   time.Now(),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	if err := os.WriteFile(credsPath, data, 0600); err != nil {
		t.Fatalf("failed to write test creds: %v", err)
	}

	origEnv := os.Getenv("BAP_CREDENTIALS")
	os.Setenv("BAP_CREDENTIALS", credsPath)
	defer os.Setenv("BAP_CREDENTIALS", origEnv)

	err := RunStatus([]string{"--json", "--no-sweep"})
	if err != nil {
		t.Fatalf("RunStatus with OTC enrolled credentials failed: %v", err)
	}

	// Verify credentials.json was NOT deleted or purged by RunStatus
	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		t.Fatalf("BUG: credentials.json was purged by RunStatus!")
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

func TestRunStatus_UnmonitoredSessionWithHooksDisabled(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)

	sDir := state.SessionsDir()
	markerPath := filepath.Join(sDir, "sess-unmonitored-test.json")
	marker := map[string]any{
		"session_id":      "sess-claude-unmonitored-1",
		"app_id":          "claude-code",
		"pid":             os.Getpid(),
		"hooks_disabled":  true,
		"reporting_layer": "unmonitored",
		"started_at":      time.Now(),
	}
	markerBytes, _ := json.Marshal(marker)
	_ = os.WriteFile(markerPath, markerBytes, 0600)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Drain concurrently: status output exceeds the OS pipe buffer, so reading
	// only after RunStatus returns deadlocks the writer.
	var buf bytes.Buffer
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(drained)
	}()

	err := RunStatus([]string{})
	w.Close()
	os.Stdout = oldStdout
	<-drained

	if err != nil {
		t.Fatalf("RunStatus failed: %v", err)
	}

	out := buf.String()

	if !strings.Contains(out, "ACTIVE (UNMONITORED)") && !strings.Contains(out, "Hooks Disabled") {
		t.Fatalf("expected status output to show unmonitored / hooks disabled session, got:\n%s", out)
	}
	if strings.Contains(out, "Active (Verified)") {
		t.Fatalf("unmonitored session must not be labeled 'Active (Verified)', got:\n%s", out)
	}
}

func TestEnsureEnrolledOrAutoFixBlocksWhenUnenrolled(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	t.Setenv("BAP_STATE_DIR", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("HOME", tmp)
	t.Setenv("BAP_CREDENTIALS", filepath.Join(tmp, "missing-credentials.json"))

	err := EnsureEnrolledOrAutoFix()
	if err == nil {
		t.Fatalf("expected error when workstation is unenrolled, got nil")
	}
	if !strings.Contains(err.Error(), "bap login") {
		t.Fatalf("expected error to instruct user to run 'bap login', got: %v", err)
	}
}

func TestEnsureEnrolledOrAutoFixAllowsOfflineWhenControlPlaneUnreachable(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	t.Setenv("BAP_STATE_DIR", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("HOME", tmp)
	credPath := filepath.Join(tmp, "credentials.json")
	t.Setenv("BAP_CREDENTIALS", credPath)

	creds := StoredCredentials{
		AgentID:      "agent-offline-1",
		SessionToken: "tok-offline-1",
		ServerURL:    "http://127.0.0.1:1",
	}
	data, _ := json.Marshal(creds)
	if err := os.WriteFile(credPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureEnrolledOrAutoFix(); err != nil {
		t.Fatalf("expected offline operation to succeed when Control Plane is unreachable, got: %v", err)
	}
}
