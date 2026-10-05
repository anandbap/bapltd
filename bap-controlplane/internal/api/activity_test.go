package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

func TestActivityEndpoints(t *testing.T) {
	s := setupTestServer()

	// 1. Test Demo Mode Simulation (?demo=true)
	t.Run("DemoModeSimulation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/activity/summary?demo=true", nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var summary types.ActivitySummary
		if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
			t.Fatalf("failed to decode summary: %v", err)
		}

		if summary.TotalActiveAgents != 1284 {
			t.Errorf("expected 1284 active agents in demo mode, got %d", summary.TotalActiveAgents)
		}
		if summary.BusinessUnitsActive != "31/34" {
			t.Errorf("expected '31/34' in demo mode, got %s", summary.BusinessUnitsActive)
		}

		// Demo topology
		reqTopo := httptest.NewRequest(http.MethodGet, "/api/activity/topology?demo=true", nil)
		recTopo := httptest.NewRecorder()
		s.mux.ServeHTTP(recTopo, reqTopo)
		var tree types.BusinessUnitTopologyNode
		if err := json.Unmarshal(recTopo.Body.Bytes(), &tree); err != nil {
			t.Fatalf("failed to decode demo topology: %v", err)
		}
		if tree.ActiveSessions != 1284 {
			t.Errorf("expected 1284 sessions in demo topology, got %d", tree.ActiveSessions)
		}
		if len(tree.Children) == 0 {
			t.Errorf("expected children in demo topology")
		}
	})

	// 2. Test Live Unsimulated Zero-State (no agents, no mock data)
	t.Run("LiveUnsimulatedZeroState", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/activity/summary", nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		var summary types.ActivitySummary
		if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
			t.Fatalf("failed to decode live summary: %v", err)
		}

		if summary.TotalActiveAgents != 0 {
			t.Errorf("expected 0 active agents in clean live state, got %d", summary.TotalActiveAgents)
		}
		if summary.BusinessUnitsActive != "0/0" {
			t.Errorf("expected '0/0' in clean live state, got %s", summary.BusinessUnitsActive)
		}

		// Live topology clean state
		reqTopo := httptest.NewRequest(http.MethodGet, "/api/activity/topology", nil)
		recTopo := httptest.NewRecorder()
		s.mux.ServeHTTP(recTopo, reqTopo)
		var tree types.BusinessUnitTopologyNode
		if err := json.Unmarshal(recTopo.Body.Bytes(), &tree); err != nil {
			t.Fatalf("failed to decode live topology: %v", err)
		}
		if tree.ActiveSessions != 0 {
			t.Errorf("expected 0 active sessions in live topology, got %d", tree.ActiveSessions)
		}
		if len(tree.Children) != 0 {
			t.Errorf("expected 0 children in live zero-state topology, got %d", len(tree.Children))
		}
	})

	// 3. Test POST /api/activity/ingest populates live data dynamically
	t.Run("LiveIngestAndDynamicAggregation", func(t *testing.T) {
		ev := types.AgentActivityEvent{
			Timestamp:          time.Now().UTC().Format(time.RFC3339),
			SessionID:          "sess-test-ingest-01",
			AgentID:            "agent-claude-test",
			AgentType:          "claude-code",
			RuntimeID:          "macbook-pro-test",
			UserID:             "engineer@enterprise.internal",
			BusinessUnit:       "Payments Engineering",
			Application:        "checkout-service",
			PromptID:           "prmpt-test-99",
			PromptSummary:      "Investigating checkout failure",
			Intent:             "PRODUCTION_DIAGNOSIS",
			IntentCategory:     "Investigate / Diagnose",
			Action:             "kubectl logs deploy/checkout-service -n prod",
			Tool:               "kubectl",
			TargetResource:     "k8s://prod/checkout-service",
			DataClassification: "Internal",
			PolicyDecision:     "ALLOW",
			RiskScore:          0.10,
			ActionStatus:       "working",
			OutcomeCategory:    "Success",
			TraceID:            "tr-test-ingest-01",
		}

		body, _ := json.Marshal(ev)
		req := httptest.NewRequest(http.MethodPost, "/api/activity/ingest", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		// Now verify GET /api/activity/live returns the real ingested event
		reqLive := httptest.NewRequest(http.MethodGet, "/api/activity/live?limit=5", nil)
		recLive := httptest.NewRecorder()
		s.mux.ServeHTTP(recLive, reqLive)

		var resp map[string]any
		_ = json.Unmarshal(recLive.Body.Bytes(), &resp)
		acts, ok := resp["activities"].([]any)
		if !ok || len(acts) != 1 {
			t.Fatalf("expected exactly 1 live activity, got %v", resp["activities"])
		}

		// Verify GET /api/activity/intents computed dynamically
		reqIntents := httptest.NewRequest(http.MethodGet, "/api/activity/intents", nil)
		recIntents := httptest.NewRecorder()
		s.mux.ServeHTTP(recIntents, reqIntents)
		var intentsResp map[string]any
		_ = json.Unmarshal(recIntents.Body.Bytes(), &intentsResp)
		intentsList, ok := intentsResp["intents"].([]any)
		if !ok || len(intentsList) == 0 {
			t.Fatalf("expected dynamic intents, got %v", intentsResp["intents"])
		}
	})

	// 4. Test GET /api/activity/deviation
	t.Run("IntentDeviationDetection", func(t *testing.T) {
		// Out-of-intent test: Production diagnosis attempting Customer DB write
		req := httptest.NewRequest(http.MethodGet, "/api/activity/deviation?intent=PRODUCTION_DIAGNOSIS&action=UPDATE+accounts+SET+balance%3D0&tool=postgres_client&target_resource=db://prod/customers", nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var rep types.IntentDeviationReport
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatalf("failed to decode deviation report: %v", err)
		}

		if rep.DeviationLevel != "CRITICAL" {
			t.Errorf("expected CRITICAL deviation for DB write during production diagnosis, got %s", rep.DeviationLevel)
		}
		if rep.PolicyDecision != "DENY" {
			t.Errorf("expected policy decision DENY, got %s", rep.PolicyDecision)
		}
		if rep.Reason == "" {
			t.Errorf("expected human-readable explanation")
		}

		// In-intent test: Refactor attempting workspace test execution
		reqOk := httptest.NewRequest(http.MethodGet, "/api/activity/deviation?intent=CODE_REFACTOR&action=pytest+tests/unit&tool=pytest&target_resource=fs://workspace", nil)
		recOk := httptest.NewRecorder()
		s.mux.ServeHTTP(recOk, reqOk)

		var repOk types.IntentDeviationReport
		if err := json.Unmarshal(recOk.Body.Bytes(), &repOk); err != nil {
			t.Fatalf("failed to decode deviation report: %v", err)
		}

		if repOk.DeviationLevel != "NONE" {
			t.Errorf("expected NONE deviation for pytest during code refactor, got %s", repOk.DeviationLevel)
		}
		if repOk.PolicyDecision != "ALLOW" {
			t.Errorf("expected policy decision ALLOW, got %s", repOk.PolicyDecision)
		}
	})
}
