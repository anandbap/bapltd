package cmd

import (
	"bap-edge/internal/state"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSupervisorRecoversCrashBacksOffAndHonorsPause(t *testing.T) {
	now := time.Now().UTC()
	controller := supervisorController{}
	launches := 0
	launch := func() error { launches++; return errors.New("synthetic launch failure") }
	controller.step(now, false, false, false, launch)
	if launches != 1 || controller.state.Status != "retrying" {
		t.Fatal(controller)
	}
	controller.step(now.Add(100*time.Millisecond), false, false, false, launch)
	if launches != 1 || controller.state.Status != "backoff" {
		t.Fatal("restart storm")
	}
	controller.step(now.Add(time.Second), true, false, false, launch)
	if launches != 1 || controller.state.Status != "paused" {
		t.Fatal("intentional stop overridden")
	}
	controller.step(now.Add(2*time.Second), false, true, true, launch)
	if controller.state.Status != "monitoring" || controller.failures != 0 {
		t.Fatal(controller)
	}
	controller.step(now.Add(3*time.Second), false, false, false, launch)
	if launches != 2 {
		t.Fatal("crashed daemon not restarted")
	}
	controller.step(now.Add(4*time.Second), false, true, false, launch)
	if launches != 2 || controller.state.Status != "unresponsive" {
		t.Fatal("unowned live process replaced")
	}
	for i := 0; i < 20; i++ {
		controller.step(now.Add(time.Duration(i+1)*time.Hour), false, false, false, launch)
	}
	if controller.state.NextAttempt.Sub(controller.state.CheckedAt) > 30*time.Second {
		t.Fatal("unbounded recovery backoff")
	}
}

func TestRuntimeLockAndPIDReuseProtection(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	release, err := acquireRuntimeLock("supervisor")
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := acquireRuntimeLock("supervisor"); !errors.Is(err, errRuntimeRunning) {
		if duplicate != nil {
			duplicate()
		}
		release()
		t.Fatal("duplicate supervisor admitted", err)
	}
	release()
	release, err = acquireRuntimeLock("supervisor")
	if err != nil {
		t.Fatal("lock not reusable", err)
	}
	release()
	if err := writeRuntimeState(DaemonConfigPath(), DaemonState{PID: os.Getpid(), ProcessBirth: "wrong-birth"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDaemonState(); err == nil {
		t.Fatal("reused PID counted as live daemon")
	}
	if _, err := os.Stat(DaemonConfigPath()); err != nil {
		t.Fatal("reader deleted shared state")
	}
}

func TestDaemonReadinessRequiresMatchingProcess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"pid": 123, "process_birth": "one"})
	}))
	defer server.Close()
	if !daemonResponsive(&DaemonState{PID: 123, ProcessBirth: "one", URL: server.URL}) {
		t.Fatal("valid health rejected")
	}
	if daemonResponsive(&DaemonState{PID: 124, ProcessBirth: "one", URL: server.URL}) || daemonResponsive(&DaemonState{PID: 123, ProcessBirth: "other", URL: server.URL}) {
		t.Fatal("foreign health accepted")
	}
}

func TestOnboardingUsesObservedCallbacksNotInstalledSettings(t *testing.T) {
	root := t.TempDir()
	t.Setenv("BAP_STATE_DIR", root)
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	now := time.Now().UTC()
	os.MkdirAll(filepath.Join(root, "reporting-health"), 0700)
	health := localOnboardingHealth(now)
	phases := health["claude_callbacks"].(map[string]any)
	if phases["PreToolUse"].(map[string]any)["status"] != "not_observed" {
		t.Fatal("hook installation inferred execution")
	}
	for event, stamp := range map[string]time.Time{"PreToolUse": now, "UserPromptSubmit": now.Add(-time.Hour), "Stop": now.Add(time.Hour)} {
		writeRuntimeState(filepath.Join(root, "reporting-health", "claude-code-"+event+".json"), map[string]any{"app": "claude-code", "event": event, "observed_at": stamp, "source": "native_callback"})
	}
	phases = localOnboardingHealth(now)["claude_callbacks"].(map[string]any)
	if phases["PreToolUse"].(map[string]any)["status"] != "observed" || phases["UserPromptSubmit"].(map[string]any)["status"] != "stale" || phases["Stop"].(map[string]any)["status"] != "not_observed" {
		t.Fatal(phases)
	}
}
