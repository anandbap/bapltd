package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withTempHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func TestWatcherAliveUsesFreshness(t *testing.T) {
	withTempHome(t)
	const sid = "sess-claude-test"
	if watcherAlive(sid) {
		t.Fatal("no liveness file must mean not alive")
	}
	p := watcherLivenessPath(sid)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if !watcherAlive(sid) {
		t.Fatal("fresh liveness file must mean alive")
	}
	old := time.Now().Add(-2 * watcherFreshness)
	_ = os.Chtimes(p, old, old)
	if watcherAlive(sid) {
		t.Fatal("stale liveness file must mean not alive")
	}
}

func TestSpoolPromptPersistsEnvelope(t *testing.T) {
	withTempHome(t)
	p := spoolPrompt("sess-x", []byte(`{"session_id":"sess-x"}`))
	if p == "" {
		t.Fatal("spoolPrompt returned no path")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"body":{"session_id":"sess-x"},"session_id":"sess-x"}` {
		t.Fatalf("unexpected envelope: %s", data)
	}
}

func TestCleanupSessionMarkersRemovesSessionFiles(t *testing.T) {
	withTempHome(t)
	const sid = "sess-cleanup-test"
	pid := 99999

	// Create test marker files
	pMarker := sessionMarkerPathForPID(pid)
	_ = os.MkdirAll(filepath.Dir(pMarker), 0700)
	_ = os.WriteFile(pMarker, []byte(`{"session_id":"`+sid+`"}`), 0600)

	sessionJson := filepath.Join(".bap", "session.json")
	_ = os.WriteFile(sessionJson, []byte(`{"session_id":"`+sid+`"}`), 0600)

	// Invoke cleanup
	cleanupSessionMarkers(sid, pid)

	if _, err := os.Stat(pMarker); !os.IsNotExist(err) {
		t.Fatalf("expected PID marker %s to be removed, err: %v", pMarker, err)
	}
	if _, err := os.Stat(sessionJson); !os.IsNotExist(err) {
		t.Fatalf("expected session.json to be removed, err: %v", err)
	}
}

func TestTransientShellDetection(t *testing.T) {
	shells := []string{"cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "conhost.exe"}
	for _, s := range shells {
		if !isTransientShell(s) {
			t.Errorf("expected %s to be classified as transient shell", s)
		}
	}
	nonShells := []string{"node.exe", "claude.exe", "bapedge.exe", "python.exe"}
	for _, ns := range nonShells {
		if isTransientShell(ns) {
			t.Errorf("expected %s not to be classified as transient shell", ns)
		}
	}
}

func TestGetParentPIDAndInspectCaller(t *testing.T) {
	myPID := os.Getpid()
	parentPID := getParentPID(myPID)
	if parentPID <= 0 {
		t.Fatalf("expected valid parent PID for current process, got %d", parentPID)
	}
	info := inspectCallerProcess(myPID)
	if info.PID != myPID {
		t.Fatalf("expected info PID %d, got %d", myPID, info.PID)
	}
	t.Logf("myPID=%d, parentPID=%d, exe=%s, app_id=%s", myPID, parentPID, info.BinaryName, info.AppID)
}
