package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestShowcaseUsesRealPinningAndIsolatedRisk(t *testing.T) {
	dir := t.TempDir()
	r := showcaseReport{RunID: "run", SessionID: "diagnostic-session"}
	if err := runShowcaseIntegrity(&r, dir); err != nil {
		t.Fatal(err)
	}
	if len(r.Evidence) != 2 || r.Evidence[0].Decision != "match" || r.Evidence[1].Decision != "mismatch" {
		t.Fatal(r.Evidence)
	}
	if _, err := os.Stat(filepath.Join(dir, "pins.json")); !os.IsNotExist(err) {
		t.Fatal("persistent pins written")
	}
	runShowcaseRisk(&r)
	if len(r.Evidence) != 6 || r.Evidence[5].Decision != "CRITICAL" {
		t.Fatal(r.Evidence)
	}
	for _, e := range r.Evidence {
		if e.RunID != "run" || e.SessionID != r.SessionID || e.Producer == "" || !e.Diagnostic || e.Timestamp.IsZero() {
			t.Fatal(e)
		}
	}
}

func TestEnforcementRiskTransitions(t *testing.T) {
	state := &sessionRiskState{}
	for i, want := range []string{"LOW", "ELEVATED", "ELEVATED", "CRITICAL"} {
		advanceSessionRisk(state, "diagnostic", time.Unix(int64(i), 0))
		if state.ThreatLevel != want || state.DenialCount != i+1 {
			t.Fatal(state)
		}
	}
}

func TestShowcaseOverrideObservationIndependentOfBuildGate(t *testing.T) {
	t.Setenv("BAP_DEV_OVERRIDE", "1")
	if active, _ := configuredDevOverride(); !active {
		t.Fatal("configured workstation override not disclosed")
	}
}

func TestShowcaseEventIDsIncludeLayer(t *testing.T) {
	r := showcaseReport{RunID: "run", SessionID: "session"}
	seen := map[string]bool{}
	for layer := 1; layer <= 5; layer++ {
		r.add(layer, "hook", "fixture", "runner", "not_reached", "not_exercised", "No evidence", nil)
	}
	for _, e := range r.Evidence {
		if seen[e.EventID] {
			t.Fatal("cross-layer event collision", e.EventID)
		}
		seen[e.EventID] = true
	}
}
