package session

import (
	"testing"
	"time"

	"bap-controlplane/internal/audit"
)

func TestObservedSessionReconciliationByPID(t *testing.T) {
	store := NewStore()

	// Case 1: Observed session arrives first, then native managed session starts
	ev := audit.Event{
		SessionID:      "observed-claude-test-pid",
		InstanceID:     "inst-alpha",
		Source:         "claude-code",
		ReportingLayer: "discovery",
		ClientPID:      5555,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := store.ReserveReportingSessions([]audit.Event{ev}, func(id string) string { return "svid:" + id }); err != nil {
		t.Fatalf("failed to reserve observed session: %v", err)
	}
	obsSess, err := store.Get("observed-claude-test-pid")
	if err != nil || obsSess.Status != "active" {
		t.Fatalf("expected active observed session, got %+v (err: %v)", obsSess, err)
	}

	// Managed session starts with same PID on same instance
	managedSess, err := store.Start(SessionStartRequest{
		SessionID:  "sess-claude-managed",
		AppID:      "claude-code",
		InstanceID: "inst-alpha",
		ClientPID:  5555,
	})
	if err != nil {
		t.Fatalf("failed to start managed session: %v", err)
	}
	if managedSess.Status != "active" {
		t.Fatalf("expected managed session to be active, got %s", managedSess.Status)
	}

	// Observed session should now be reconciled to managed session
	reconciledObs, err := store.Get("observed-claude-test-pid")
	if err != nil {
		t.Fatalf("failed to get reconciled observed session: %v", err)
	}
	if reconciledObs.Status != "reconciled" {
		t.Fatalf("expected status 'reconciled', got %q", reconciledObs.Status)
	}
	if reconciledObs.ReconciledTo != "sess-claude-managed" {
		t.Fatalf("expected ReconciledTo 'sess-claude-managed', got %q", reconciledObs.ReconciledTo)
	}

	// Case 2: Managed session starts first, then observed session event arrives
	_, err = store.Start(SessionStartRequest{
		SessionID:  "sess-codex-managed",
		AppID:      "codex",
		InstanceID: "inst-alpha",
		ClientPID:  7777,
	})
	if err != nil {
		t.Fatalf("failed to start second managed session: %v", err)
	}

	ev2 := audit.Event{
		SessionID:      "observed-codex-test-pid",
		InstanceID:     "inst-alpha",
		Source:         "codex",
		ReportingLayer: "discovery",
		ClientPID:      7777,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := store.ReserveReportingSessions([]audit.Event{ev2}, func(id string) string { return "svid:" + id }); err != nil {
		t.Fatalf("failed to reserve second observed session: %v", err)
	}
	reconciledObs2, err := store.Get("observed-codex-test-pid")
	if err != nil {
		t.Fatalf("failed to get second observed session: %v", err)
	}
	if reconciledObs2.Status != "reconciled" {
		t.Fatalf("expected status 'reconciled', got %q", reconciledObs2.Status)
	}
	if reconciledObs2.ReconciledTo != "sess-codex-managed" {
		t.Fatalf("expected ReconciledTo 'sess-codex-managed', got %q", reconciledObs2.ReconciledTo)
	}
}
