package api

import (
	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLiveSummarySeparatesObservedRecordsFromUnverifiedWork(t *testing.T) {
	s := setupTestServer()
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "coding", AppID: "claude-code", UserEmail: "user@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for _, event := range []audit.Event{{EventID: "allow", Decision: "allow", Timestamp: stamp}, {EventID: "deny", Decision: "deny", Timestamp: stamp}, {EventID: "presence", Decision: "observed", ReportingLayer: "discovery", Timestamp: stamp}} {
		s.sessionStore.RecordEvent("coding", event)
	}
	// Same operation reported through the bounded feed must not double counters.
	s.IngestActivity(&types.AgentActivityEvent{SessionID: "coding", PolicyDecision: "ALLOW", ActionStatus: "completed", IntentCategory: "Bug Fix"})
	s.IngestActivity(&types.AgentActivityEvent{SessionID: "external", PolicyDecision: "UNKNOWN", ActionStatus: "completed"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/activity/summary", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var summary map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"completed_work_count", "active_work_count", "work_intents_completed", "estimated_assisted_hours", "assisted_fte_equivalent", "governed_percent", "governed_agent_users", "high_risk_prevented", "category_trends", "business_units_active"} {
		if value, ok := summary[key]; !ok || value != nil {
			t.Fatalf("%s manufactured: %v", key, value)
		}
	}
	for key, want := range map[string]float64{"active_session_count": 1, "session_operation_records": 2, "allowed_operation_records": 1, "denied_operation_records": 1, "operation_allowance_percent": 50, "activity_records_retained": 2, "activity_unknown_decision_records": 1, "unlinked_activity_records": 1, "observed_session_users": 1} {
		if summary[key] != want {
			t.Fatalf("%s = %v want %v", key, summary[key], want)
		}
	}
	if summary["simulated"] != false || summary["mode"] != "live" {
		t.Fatal(summary)
	}
	if got := summary["category_mix"].(map[string]any)["Other / Unclassified"]; got != float64(100) {
		t.Fatal("platform name inferred work category", summary["category_mix"])
	}
}

func TestEmptyLiveSummaryDoesNotClaimPerfectGovernance(t *testing.T) {
	summary := setupTestServer().liveActivitySummary()
	if summary["governed_percent"] != nil || summary["operation_allowance_percent"] != nil || summary["session_operation_records"] != 0 {
		t.Fatal(summary)
	}
}

func TestChainVerificationDoesNotCertifyComplianceOrCompleteCollection(t *testing.T) {
	s := setupTestServer()
	w := httptest.NewRecorder()
	s.handleVerifyChain(w, httptest.NewRequest("GET", "/verify", nil))
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["valid"] != true || result["compliance_status"] != "not_assessed" || result["collection_completeness"] != "unknown" || result["merkle_integrity"] != "not_evaluated" {
		t.Fatal(result)
	}
}
