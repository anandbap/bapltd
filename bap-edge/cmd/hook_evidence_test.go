package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"bap-edge/internal/audit"
	"bap-edge/internal/state"
)

func TestHookEvidencePromotionAndRetry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAP_STATE_DIR", dir)
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	log := filepath.Join(dir, "audit.jsonl")
	t.Setenv("BAP_AUDIT_LOG", log)
	spool := filepath.Join(dir, "hook-evidence")
	_ = os.MkdirAll(spool, 0700)
	path := filepath.Join(spool, "hook-example.json")
	data := []byte(`{"event_id":"hook-example","session_id":"codex-file","reporting_layer":"hook","source":"codex","decision":"deny","full_command":"Read workspace/file.go"}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := collectHookEvidence(); err != nil || n != 1 {
		t.Fatalf("promotion: %d %v", n, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("source was not removed after synchronized journal handoff")
	}
	entries, err := audit.ReadEntries(log)
	if err != nil || len(entries) != 1 || entries[0].ReportingLayer != "hook" {
		t.Fatalf("durable promotion lost: %v %v", entries, err)
	}
	if valid, _, err := audit.VerifyLocalLog(log); !valid || err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BAP_AUDIT_LOG", filepath.Join(dir, "absent-parent", "journal.jsonl"))
	// Force a persistence failure without touching any machine state.
	if err := os.WriteFile(filepath.Join(dir, "absent-parent"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := collectHookEvidence(); err == nil {
		t.Fatal("persistence failure was hidden")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("failed handoff deleted producer's record")
	}
}
