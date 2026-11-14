package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/audit"
)

func resetReportState(t *testing.T) *[]audit.AuditEntry {
	t.Helper()
	reportedTurnsMu.Lock()
	reportedTurns = map[string]struct{}{}
	reportedTurnsMu.Unlock()
	var got []audit.AuditEntry
	orig := emitReport
	emitReport = func(e audit.AuditEntry, _ ServerConfig) { got = append(got, e) }
	t.Cleanup(func() { emitReport = orig })
	return &got
}

func touchHeartbeat(t *testing.T, stateDir, sessionID string, modTime time.Time) {
	t.Helper()
	dir := filepath.Join(stateDir, "hook-heartbeat")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, hookHeartbeatFile(sessionID))
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, modTime, modTime); err != nil {
		t.Fatal(err)
	}
}

func TestReportRequestDisabledByDefault(t *testing.T) {
	got := resetReportState(t)
	t.Setenv(fallbackFlagEnvVar, "")
	res := reportRequest(map[string]interface{}{"request_summary": "fix bug"}, ServerConfig{SessionID: "s1"}, t.TempDir(), time.Now())
	if len(*got) != 0 || !strings.Contains(res.Content[0].Text, "fallback_reporting_disabled") {
		t.Fatalf("must not record when disabled: %+v %+v", *got, res)
	}
}

func TestReportRequestRequiresSummary(t *testing.T) {
	got := resetReportState(t)
	t.Setenv(fallbackFlagEnvVar, "1")
	res := reportRequest(map[string]interface{}{}, ServerConfig{SessionID: "s1"}, t.TempDir(), time.Now())
	if !res.IsError || len(*got) != 0 {
		t.Fatalf("empty summary must be rejected: %+v", res)
	}
}

func TestReportRequestDroppedWhenHookActive(t *testing.T) {
	got := resetReportState(t)
	t.Setenv(fallbackFlagEnvVar, "1")
	dir := t.TempDir()
	now := time.Now()
	touchHeartbeat(t, dir, "s1", now.Add(-5*time.Second))
	res := reportRequest(map[string]interface{}{"request_summary": "fix bug", "turn_id": "t1"}, ServerConfig{SessionID: "s1"}, dir, now)
	if len(*got) != 0 || !strings.Contains(res.Content[0].Text, "hook_active") {
		t.Fatalf("hook-active session must not be double reported: %+v %+v", *got, res)
	}
}

func TestReportRequestRecordsSelfReportedWhenHookStale(t *testing.T) {
	got := resetReportState(t)
	t.Setenv(fallbackFlagEnvVar, "1")
	dir := t.TempDir()
	now := time.Now()
	touchHeartbeat(t, dir, "s1", now.Add(-5*time.Minute))
	res := reportRequest(map[string]interface{}{"request_summary": "fix bug", "turn_id": "t1"}, ServerConfig{SessionID: "s1"}, dir, now)
	if len(*got) != 1 {
		t.Fatalf("want 1 record, got %d (%+v)", len(*got), res)
	}
	e := (*got)[0]
	if e.ReportingLayer != "mcp" || e.EvidenceGrade != "self_reported" || e.TurnID != "t1" ||
		e.Executable != "user_prompt" || e.Decision != "observed" || e.SessionID != "s1" {
		t.Fatalf("unexpected entry: %+v", e)
	}
}

func TestReportRequestRecordsWhenNoHeartbeatAndDedupsTurn(t *testing.T) {
	got := resetReportState(t)
	t.Setenv(fallbackFlagEnvVar, "1")
	dir := t.TempDir()
	args := map[string]interface{}{"request_summary": "fix bug", "turn_id": "t9"}
	reportRequest(args, ServerConfig{SessionID: "s2"}, dir, time.Now())
	res := reportRequest(args, ServerConfig{SessionID: "s2"}, dir, time.Now())
	if len(*got) != 1 || !strings.Contains(res.Content[0].Text, "duplicate_turn") {
		t.Fatalf("same turn must record once: %d %+v", len(*got), res)
	}
}

func TestHookHeartbeatFileSanitizesTraversal(t *testing.T) {
	name := hookHeartbeatFile("../../etc/passwd")
	if strings.ContainsAny(name, `/\`) {
		t.Fatalf("unsafe heartbeat name: %q", name)
	}
	if hookRecentlyActive(t.TempDir(), "..", time.Minute, time.Now()) {
		t.Fatal(".. must never match a heartbeat")
	}
}
