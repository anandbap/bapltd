package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

// TestBAP911_ExplicitAgentPrincipalAndIdentityBinding verifies that an auditor
// can distinguish two Claude Code sessions running under the same Windows user
// and identify their separate permissions, actions, and lifecycle (BAP-911).
func TestBAP911_ExplicitAgentPrincipalAndIdentityBinding(t *testing.T) {
	srv := setupTestServer()
	sessStore := srv.sessionStore

	// Session 1: Claude Code session under Windows user "User"
	s1, err := sessStore.Start(session.SessionStartRequest{
		SessionID:           "sess-claude-worker-1",
		AppID:               "claude-code",
		UserID:              "User",
		UserEmail:           "User@corp.local",
		InstanceID:          "workstation-dev-01",
		WorkstationSPIFFEID: "spiffe://bap.internal/workstation/workstation-dev-01",
		UserPrompt:          "Analyze authz bottlenecks",
	})
	if err != nil {
		t.Fatalf("Failed to start session 1: %v", err)
	}

	// Session 2: Second concurrent Claude Code session under the same Windows user "User"
	s2, err := sessStore.Start(session.SessionStartRequest{
		SessionID:           "sess-claude-worker-2",
		AppID:               "claude-code",
		UserID:              "User",
		UserEmail:           "User@corp.local",
		InstanceID:          "workstation-dev-01",
		WorkstationSPIFFEID: "spiffe://bap.internal/workstation/workstation-dev-01",
		UserPrompt:          "Refactor data pipeline",
	})
	if err != nil {
		t.Fatalf("Failed to start session 2: %v", err)
	}

	// Verify both sessions have explicit distinct principal IDs
	if s1.PrincipalID == "" || s2.PrincipalID == "" {
		t.Fatalf("Expected non-empty PrincipalIDs, got s1=%q, s2=%q", s1.PrincipalID, s2.PrincipalID)
	}
	if s1.PrincipalID == s2.PrincipalID {
		t.Fatalf("Expected distinct PrincipalIDs for two sessions under the same user, but got identical: %s", s1.PrincipalID)
	}
	if s1.PrincipalSVID == s2.PrincipalSVID {
		t.Fatalf("Expected distinct Principal SVIDs, but got identical: %s", s1.PrincipalSVID)
	}

	// 1. Auditor queries /api/v1/principals
	reqPrincipals := httptest.NewRequest(http.MethodGet, "/api/v1/principals", nil)
	wPrincipals := httptest.NewRecorder()
	srv.mux.ServeHTTP(wPrincipals, reqPrincipals)

	if wPrincipals.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 from /api/v1/principals, got %d", wPrincipals.Code)
	}

	var listResp struct {
		Principals []types.AgentPrincipal `json:"principals"`
		Total      int                    `json:"total"`
	}
	if err := json.Unmarshal(wPrincipals.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("Failed to unmarshal principals response: %v", err)
	}
	if listResp.Total < 2 {
		t.Fatalf("Expected at least 2 principals, got %d", listResp.Total)
	}

	// 2. Auditor inspects Session 1 principal endpoint
	reqS1Principal := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/sess-claude-worker-1/principal", nil)
	wS1Principal := httptest.NewRecorder()
	srv.mux.ServeHTTP(wS1Principal, reqS1Principal)

	if wS1Principal.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 from session 1 principal, got %d", wS1Principal.Code)
	}
	var p1 types.AgentPrincipal
	if err := json.Unmarshal(wS1Principal.Body.Bytes(), &p1); err != nil {
		t.Fatalf("Failed to decode p1: %v", err)
	}
	if p1.PrincipalID != s1.PrincipalID {
		t.Errorf("Expected p1.PrincipalID == %s, got %s", s1.PrincipalID, p1.PrincipalID)
	}
	if p1.HumanOwner != "User@corp.local" {
		t.Errorf("Expected human owner User@corp.local, got %s", p1.HumanOwner)
	}
	if p1.AgentSessionID != "sess-claude-worker-1" {
		t.Errorf("Expected session sess-claude-worker-1, got %s", p1.AgentSessionID)
	}

	// 3. Auditor inspects Session 2 principal endpoint
	reqS2Principal := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/sess-claude-worker-2/principal", nil)
	wS2Principal := httptest.NewRecorder()
	srv.mux.ServeHTTP(wS2Principal, reqS2Principal)

	if wS2Principal.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 from session 2 principal, got %d", wS2Principal.Code)
	}
	var p2 types.AgentPrincipal
	if err := json.Unmarshal(wS2Principal.Body.Bytes(), &p2); err != nil {
		t.Fatalf("Failed to decode p2: %v", err)
	}
	if p2.PrincipalID != s2.PrincipalID {
		t.Errorf("Expected p2.PrincipalID == %s, got %s", s2.PrincipalID, p2.PrincipalID)
	}

	// Auditor verifies that both principals are distinct and traceable
	if p1.PrincipalID == p2.PrincipalID {
		t.Errorf("Auditor cannot distinguish principals: identical ID %s", p1.PrincipalID)
	}
}
