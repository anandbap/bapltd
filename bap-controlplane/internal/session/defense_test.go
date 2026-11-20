package session

import (
	"bap-controlplane/internal/audit"
	"bap-controlplane/pkg/types"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveDefensePersistsWithoutInventingOtherLayers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	store, err := NewStoreWithDB(path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	obs := []types.DefenseObservation{{EventID: "broker-check", ActionID: "action-a", Layer: 2, Producer: "edge/execution-broker", Decision: "ALLOWED_EXECUTED", Timestamp: stamp}, {EventID: "integrity-check", ActionID: "action-a", Layer: 3, Producer: "edge/file-integrity", Decision: "passed", Timestamp: stamp}}
	store.RecordEvent("live-session", audit.Event{EventID: "action-a", SessionID: "live-session", ReportingLayer: "broker", Source: "codex", Decision: "allow", Timestamp: stamp, DefenseObservations: obs})
	check := func(s *Store) {
		summary, err := s.GetSummary("live-session")
		if err != nil {
			t.Fatal(err)
		}
		if len(summary.DefenseLayers) != 5 || summary.TotalEvents != 1 {
			t.Fatal(summary)
		}
		for i, want := range []string{"not_observed", "evaluated", "evaluated", "not_observed", "not_observed"} {
			if summary.DefenseLayers[i].State != want {
				t.Fatal(i, summary.DefenseLayers)
			}
		}
		if summary.DefenseLayers[1].Evidence.ActionID != "action-a" {
			t.Fatal("action correlation lost")
		}
	}
	check(store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := NewStoreWithDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	check(restored)
}

func TestDiagnosticEvidenceDoesNotBecomeLiveCoverage(t *testing.T) {
	s := NewStore()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	s.RecordEvent("diagnostic-fixture", audit.Event{EventID: "fixture", SessionID: "diagnostic-fixture", ReportingLayer: "hook", Decision: "allow", Timestamp: stamp, DefenseObservations: []types.DefenseObservation{{EventID: "fixture", ActionID: "fixture", Layer: 1, Producer: "native-hook", Decision: "allow", Timestamp: stamp}}})
	summary, _ := s.GetSummary("diagnostic-fixture")
	for _, l := range summary.DefenseLayers {
		if l.State != "not_observed" {
			t.Fatal("fixture promoted to live evidence", l)
		}
	}
}

func TestLiveDefenseDoesNotMergeDistinctActionsByCommandSimilarity(t *testing.T) {
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	var events []audit.Event
	for i, layer := range []string{"hook", "broker"} {
		id := []string{"first-action", "second-action"}[i]
		events = append(events, audit.Event{EventID: id, SessionID: "s", ReportingLayer: layer, FullCommand: "git status", Timestamp: stamp, DefenseObservations: []types.DefenseObservation{{EventID: id, ActionID: id, Layer: i + 1}}})
	}
	if got := Arbitrate(events); len(got) != 2 {
		t.Fatalf("distinct actions merged: %+v", got)
	}
}
