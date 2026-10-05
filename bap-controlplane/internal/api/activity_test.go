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

	// 1. Test GET /api/activity/summary
	t.Run("ActivitySummary", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/activity/summary", nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var summary types.ActivitySummary
		if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
			t.Fatalf("failed to decode summary: %v", err)
		}

		if summary.TotalActiveAgents <= 0 {
			t.Errorf("expected positive active agents, got %d", summary.TotalActiveAgents)
		}
		if summary.BusinessUnitsActive == "" {
			t.Errorf("expected non-empty business units active string")
		}
	})

	// 2. Test GET /api/activity/live
	t.Run("ActivityLive", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/activity/live?limit=5", nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode live response: %v", err)
		}

		acts, ok := resp["activities"].([]any)
		if !ok || len(acts) == 0 {
			t.Fatalf("expected non-empty activities list, got %v", resp["activities"])
		}
	})

	// 3. Test GET /api/activity/intents
	t.Run("ActivityIntents", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/activity/intents", nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode intents: %v", err)
		}

		intents, ok := resp["intents"].([]any)
		if !ok || len(intents) == 0 {
			t.Fatalf("expected intents list, got %v", resp["intents"])
		}
	})

	// 4. Test GET /api/activity/business-units
	t.Run("ActivityBusinessUnits", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/activity/business-units", nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode business-units: %v", err)
		}

		bus, ok := resp["business_units"].([]any)
		if !ok || len(bus) == 0 {
			t.Fatalf("expected business units list, got %v", resp["business_units"])
		}
	})

	// 5. Test GET /api/activity/topology
	t.Run("ActivityTopology", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/activity/topology?group_by=bu", nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var tree types.BusinessUnitTopologyNode
		if err := json.Unmarshal(rec.Body.Bytes(), &tree); err != nil {
			t.Fatalf("failed to decode topology tree: %v", err)
		}

		if tree.Name != "Enterprise AI Workforce" {
			t.Errorf("expected root name 'Enterprise AI Workforce', got %s", tree.Name)
		}
		if len(tree.Children) == 0 {
			t.Errorf("expected children nodes under topology root")
		}
	})

	// 6. Test POST /api/activity/ingest
	t.Run("ActivityIngest", func(t *testing.T) {
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
	})

	// 7. Test GET /api/activity/deviation
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
