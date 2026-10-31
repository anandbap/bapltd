package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/state"
)

func TestAgentObservationWithoutNativeHooks(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	log := filepath.Join(t.TempDir(), "observations.jsonl")
	t.Setenv("BAP_AUDIT_LOG", log)
	s, _ := NewDaemonServer("off", 0)
	p := agentProcess{PID: 1234, ParentPID: 1, Name: "codex.exe", Birth: "first-birth"}
	processes := []agentProcess{p, {PID: 5678, ParentPID: 1234, Name: "powershell.exe"}}
	caller, found := observedCaller(5678, processes)
	if !found || caller.PID != 1234 {
		t.Fatal("intermediary shell hid agent attribution")
	}
	s.reconcileObservedProcesses(processes, "installation-a")
	s.reconcileObservedProcesses(processes, "installation-a")
	entries, err := audit.ReadEntries(log)
	if err != nil || len(entries) != 1 {
		t.Fatalf("presence not persisted once: %v %v", entries, err)
	}
	if entries[0].ReportingLayer != "discovery" || entries[0].Decision != "observed" || entries[0].UserPrompt != "" {
		t.Fatalf("fabricated coverage: %+v", entries[0])
	}
	id := observedSessionID("installation-a", p)
	if s.sessions[id].PID != 1234 {
		t.Fatal("workload not attached for independent heartbeats")
	}
	p.Birth = "replacement-birth"
	s.reconcileObservedProcesses([]agentProcess{p}, "installation-a")
	if _, exists := s.sessions[id]; exists {
		t.Fatal("PID reuse kept prior session alive")
	}
	if observedSessionID("installation-a", p) == observedSessionID("installation-b", p) {
		t.Fatal("workstation scope missing")
	}
	if observedSessionID("installation-a", agentProcess{PID: 2, Name: "codex-helper.exe", Birth: "now"}) != "" {
		t.Fatal("generic helper misidentified as agent")
	}
	if _, err := os.Stat(log); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSessionSuppressesDuplicateDiscovery(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	t.Setenv("BAP_AUDIT_LOG", filepath.Join(t.TempDir(), "observations.jsonl"))
	s, _ := NewDaemonServer("off", 0)
	s.sessions["native-session"] = AttachedSession{SessionID: "native-session", PID: 42, AppID: "codex", ReportingLayer: "hook"}
	s.reconcileObservedProcesses([]agentProcess{{PID: 42, Name: "codex", Birth: "birth"}}, "installation")
	if len(s.sessions) != 1 {
		t.Fatal("duplicate workload card")
	}
}

func TestNativeProcessObservationMetadata(t *testing.T) {
	processes, err := listAgentProcesses()
	if err != nil {
		t.Skipf("platform process observation unavailable: %v", err)
	}
	for _, p := range processes {
		if p.PID == os.Getpid() {
			return
		}
	}
	t.Fatal("native process enumeration missed current process")
}

func TestNativeMarkerRequiresProcessBirthAndDestination(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	t.Setenv("BAP_AUDIT_LOG", filepath.Join(t.TempDir(), "observations.jsonl"))
	s, _ := NewDaemonServer("off", 0)
	p := agentProcess{PID: 42, Name: "codex.exe", Birth: "current-birth"}
	_ = os.MkdirAll(state.SessionsDir(), 0700)
	marker := map[string]any{"session_id": "old-native", "server_url": "off", "pid": 42, "process_birth": "previous-birth"}
	data, _ := json.Marshal(marker)
	_ = os.WriteFile(sessionPIDMarkerPath(42), data, 0600)
	s.reconcileObservedProcesses([]agentProcess{p}, "installation")
	if _, ok := s.sessions["old-native"]; ok {
		t.Fatal("PID-reused marker adopted")
	}
	marker["process_birth"] = "current-birth"
	marker["server_url"] = "https://other.example"
	data, _ = json.Marshal(marker)
	_ = os.WriteFile(sessionPIDMarkerPath(42), data, 0600)
	s.reconcileObservedProcesses([]agentProcess{p}, "installation")
	if _, ok := s.sessions["old-native"]; ok {
		t.Fatal("cross-destination marker adopted")
	}
	marker["server_url"] = "off"
	data, _ = json.Marshal(marker)
	_ = os.WriteFile(sessionPIDMarkerPath(42), data, 0600)
	s.reconcileObservedProcesses([]agentProcess{p}, "installation")
	if len(s.sessions) != 1 || s.sessions["old-native"].PID != 42 {
		t.Fatal("native session duplicated instead of replacing fallback observation")
	}
}

func TestFullDeliveryQueueRetainsIndependentObservation(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	log := filepath.Join(t.TempDir(), "observations.jsonl")
	t.Setenv("BAP_AUDIT_LOG", log)
	s, _ := NewDaemonServer("off", 0)
	for i := 0; i < cap(s.eventQueue); i++ {
		s.eventQueue <- audit.AuditEntry{}
	}
	done := make(chan struct{})
	go func() {
		s.reconcileObservedProcesses([]agentProcess{{PID: 42, Name: "codex", Birth: "birth"}}, "installation")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("saturated live queue blocked discovery")
	}
	entries, err := audit.ReadEntries(log)
	if err != nil || len(entries) != 1 {
		t.Fatalf("queue saturation lost persistent event: %v %v", entries, err)
	}
}
