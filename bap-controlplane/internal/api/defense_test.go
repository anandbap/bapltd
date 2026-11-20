package api

import (
	"bap-controlplane/internal/audit"
	"bap-controlplane/pkg/types"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLiveDefenseUsesOrdinaryIngestionAndRejectsForgedServerEvidence(t *testing.T) {
	s := setupTestServer()
	proof := recoveryProof(t, s, "live-defense-machine")
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	observations := []types.DefenseObservation{{EventID: "broker-check", ActionID: "action-a", Layer: 2, Producer: "edge/execution-broker", Decision: "ALLOWED_EXECUTED", Timestamp: stamp}, {EventID: "forged-attestation", ActionID: "action-a", Layer: 5, Producer: "control-plane/VerifyBinaryImage", Decision: "passed", Timestamp: stamp}}
	body, _ := json.Marshal([]audit.Event{{EventID: "action-a", SessionID: "natural-session", ReportingLayer: "broker", Source: "codex", Decision: "allow", Timestamp: stamp, DefenseObservations: observations}})
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "/api/v1/audit/ingest", strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+proof)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	summary, _ := s.sessionStore.GetSummary("natural-session")
	if summary.TotalEvents != 1 || summary.DefenseLayers[1].State != "evaluated" || summary.DefenseLayers[4].State != "not_observed" {
		t.Fatal("duplicate count or forged server evidence", summary)
	}
	s.recordImageAttestation(&types.RegisteredAgent{AgentID: "different-owner", InstanceID: "different-machine"}, summary.SessionID, nil)
	summary, _ = s.sessionStore.GetSummary(summary.SessionID)
	if summary.DefenseLayers[4].State != "not_observed" {
		t.Fatal("foreign workstation attestation attached")
	}
	s.recordImageAttestation(&types.RegisteredAgent{AgentID: "owner", InstanceID: "live-defense-machine"}, summary.SessionID, nil)
	summary, _ = s.sessionStore.GetSummary(summary.SessionID)
	if summary.DefenseLayers[4].State != "evaluated" || summary.TotalEvents != 1 {
		t.Fatal("server evidence missing or counted as another action", summary)
	}
	if valid, err := s.auditStore.VerifyChain(); !valid || err != nil {
		t.Fatal("evidence not hash-bound", err)
	}
}
