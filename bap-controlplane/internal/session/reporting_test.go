package session

import (
	"path/filepath"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
)

func TestReportingWithoutPromptsPreservesCountsAndFreeze(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	s, err := NewStoreWithDB(path)
	if err != nil {
		t.Fatal(err)
	}
	ev := audit.Event{SessionID: "observed-codex", InstanceID: "machine", Source: "codex", ReportingLayer: "discovery", Decision: "observed", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	s.RecordEvent(ev.SessionID, ev)
	got, _ := s.GetSummary(ev.SessionID)
	if got.TotalEvents != 0 || got.AllowedCount != 0 || got.UserPrompt != "" || got.GrantID != "" {
		t.Fatalf("presence became authorization: %+v", got)
	}
	ev.ReportingLayer, ev.Decision = "broker", "deny"
	s.RecordEvent(ev.SessionID, ev)
	s.RecordEvent(ev.SessionID, ev)
	if err := s.RevokeSession(ev.SessionID, "Frozen by administrator"); err != nil {
		t.Fatal(err)
	}
	ev.ReportingLayer, ev.Decision = "discovery", "observed"
	s.RecordEvent(ev.SessionID, ev)
	got, _ = s.GetSummary(ev.SessionID)
	if got.Status != "revoked" || got.TotalEvents != 2 || got.DeniedCount != 2 || len(got.ReportingLayers) != 2 {
		t.Fatalf("reporting cleared freeze or distorted counts: %+v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStoreWithDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, _ = s.GetSummary(ev.SessionID)
	if len(got.ReportingLayers) != 2 || got.Status != "revoked" {
		t.Fatalf("reporting coverage lost on reopen: %+v", got)
	}
}
