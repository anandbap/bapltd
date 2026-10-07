package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

func TestAPIDelegateGrant_SuccessAndPrivilegeEscalationBlocked(t *testing.T) {
	srv := setupTestServer()
	srv.SetAdminSecurity("test-admin", true)

	rootAgent := &types.RegisteredAgent{
		AgentID:         "root-orchestrator",
		AppID:           "claude-code",
		AgentName:       "root-orchestrator",
		PermittedScopes: []string{"fs:read", "fs:write", "api:read"},
	}
	parentToken, _, parentGrantID, err := srv.minter.MintWithDetails(
		rootAgent,
		"bin-hash-1",
		[]string{"fs:read", "fs:write", "api:read"},
		"sess-root",
		"exec",
		"/workspace/*",
		nil,
		"v1",
	)
	if err != nil {
		t.Fatalf("failed to mint parent token: %v", err)
	}

	// 1. Success: child requests attenuated subset ["fs:read"]
	delReqValid := types.DelegateGrantRequest{
		ParentToken:     parentToken,
		ChildAgentID:    "subagent-coder",
		ChildAppID:      "claude-subagent",
		SessionID:       "sess-child-101",
		RequestedScopes: []string{"fs:read"},
		Action:          "exec",
		Resource:        "/workspace/src/*",
		TTLMins:         10,
	}
	body, _ := json.Marshal(delReqValid)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/grants/delegate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid delegation, got %d: %s", w.Code, w.Body.String())
	}

	var delResp types.DelegateGrantResponse
	if err := json.Unmarshal(w.Body.Bytes(), &delResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if delResp.ParentGrantID != parentGrantID {
		t.Fatalf("expected ParentGrantID %s, got %s", parentGrantID, delResp.ParentGrantID)
	}
	if delResp.RootAgentID != "root-orchestrator" {
		t.Fatalf("expected RootAgentID 'root-orchestrator', got %s", delResp.RootAgentID)
	}
	expectedTree := "root-orchestrator -> subagent-coder"
	if delResp.LineageTree != expectedTree {
		t.Fatalf("expected lineage tree %q, got %q", expectedTree, delResp.LineageTree)
	}

	// 2. Escalation Blocked: child requests scope broader than parent (e.g. admin:all)
	delReqEscalated := types.DelegateGrantRequest{
		ParentToken:     parentToken,
		ChildAgentID:    "subagent-malicious",
		SessionID:       "sess-child-102",
		RequestedScopes: []string{"fs:read", "admin:all"},
		Action:          "exec",
		Resource:        "/workspace/src/*",
	}
	bodyEsc, _ := json.Marshal(delReqEscalated)
	reqEsc := httptest.NewRequest(http.MethodPost, "/api/v1/grants/delegate", bytes.NewReader(bodyEsc))
	wEsc := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wEsc, reqEsc)

	if wEsc.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for escalation, got %d: %s", wEsc.Code, wEsc.Body.String())
	}
	if !strings.Contains(wEsc.Body.String(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked error in body, got: %s", wEsc.Body.String())
	}
}

func TestAPIRootRevocation_CascadesToDescendants(t *testing.T) {
	srv := setupTestServer()
	srv.SetAdminSecurity("test-admin", true)

	rootAgent := &types.RegisteredAgent{
		AgentID:         "root-orchestrator",
		AppID:           "claude-code",
		AgentName:       "root-orchestrator",
		PermittedScopes: []string{"fs:read", "fs:write"},
	}
	srv.registry.EnsureSessionAgent("claude-code", "root-orchestrator", "", "", "", "root-orchestrator")
	parentToken, _, parentGrantID, _ := srv.minter.MintWithDetails(
		rootAgent,
		"bin-hash-1",
		[]string{"fs:read", "fs:write"},
		"sess-root-1",
		"exec",
		"/workspace/*",
		nil,
		"v1",
	)

	// Register root session in sessionStore before delegation
	if srv.sessionStore != nil {
		_, _ = srv.sessionStore.Start(session.SessionStartRequest{
			SessionID:  "sess-root-1",
			AppID:      "claude-code",
			InstanceID: "root-orchestrator",
			AgentName:  "root-orchestrator",
			GrantID:    parentGrantID,
		})
	}

	// Delegate to child
	delReq := types.DelegateGrantRequest{
		ParentToken:     parentToken,
		ChildAgentID:    "subagent-worker",
		SessionID:       "sess-worker-1",
		RequestedScopes: []string{"fs:read"},
	}
	body, _ := json.Marshal(delReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/grants/delegate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delegation failed: %s", w.Body.String())
	}

	var delResp types.DelegateGrantResponse
	_ = json.Unmarshal(w.Body.Bytes(), &delResp)
	childGrantID := delResp.GrantID
	childToken := delResp.Token

	// Now revoke root orchestrator via /api/v1/control/agent/kill with action: "revoke"
	killReq := map[string]string{
		"target": "root-orchestrator",
		"action": "revoke",
	}
	kBody, _ := json.Marshal(killReq)
	rKill := httptest.NewRequest(http.MethodPost, "/api/v1/control/agent/kill", bytes.NewReader(kBody))
	rKill.Header.Set("X-BAP-Admin-Token", "test-admin")
	wKill := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wKill, rKill)

	if wKill.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for kill/revoke, got %d: %s", wKill.Code, wKill.Body.String())
	}

	// Verify child grant is revoked
	if isRev, _ := srv.minter.IsGrantRevoked(childGrantID); !isRev {
		t.Fatalf("expected child grant %s to be revoked following root revocation", childGrantID)
	}

	// Child heartbeat must now return revoked and terminate
	hbReq := map[string]string{
		"session_id": "sess-worker-1",
	}
	hbBody, _ := json.Marshal(hbReq)
	rHB := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/heartbeat", bytes.NewReader(hbBody))
	wHB := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wHB, rHB)

	var hbResp struct {
		Status string `json:"status"`
		Action string `json:"action"`
	}
	_ = json.Unmarshal(wHB.Body.Bytes(), &hbResp)
	if hbResp.Status != "revoked" || hbResp.Action != "terminate" {
		t.Fatalf("expected heartbeat response status: revoked, action: terminate; got: %+v", hbResp)
	}

	// Verify child token is rejected
	if _, err := srv.minter.Verify(childToken); err == nil {
		t.Fatalf("expected child token verification to fail after root revocation, got nil")
	}
}

func TestAPILineageAndTopology(t *testing.T) {
	srv := setupTestServer()
	srv.SetAdminSecurity("test-admin", true)

	rootAgent := &types.RegisteredAgent{
		AgentID:         "root-orchestrator",
		AppID:           "claude-code",
		AgentName:       "root-orchestrator",
		PermittedScopes: []string{"fs:read", "fs:write"},
	}
	parentToken, _, _, _ := srv.minter.MintWithDetails(
		rootAgent,
		"bin-hash-1",
		[]string{"fs:read", "fs:write"},
		"sess-top-root",
		"exec",
		"/workspace/*",
		nil,
		"v1",
	)

	// Delegate to child
	delReq := types.DelegateGrantRequest{
		ParentToken:     parentToken,
		ChildAgentID:    "subagent-designer",
		SessionID:       "sess-top-child",
		RequestedScopes: []string{"fs:read"},
	}
	body, _ := json.Marshal(delReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/grants/delegate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delegation failed: %s", w.Body.String())
	}

	// Start root and child sessions in store
	if srv.sessionStore != nil {
		_, _ = srv.sessionStore.Start(session.SessionStartRequest{
			SessionID: "sess-top-root",
			AppID:     "claude-code",
			AgentName: "root-orchestrator",
		})
		_, _ = srv.sessionStore.Start(session.SessionStartRequest{
			SessionID:       "sess-top-child",
			AppID:           "claude-code",
			AgentName:       "subagent-designer",
			ParentSessionID: "sess-top-root",
			RootAgentID:     "root-orchestrator",
			Lineage:         []string{"root-orchestrator", "subagent-designer"},
			LineageTree:     "root-orchestrator -> subagent-designer",
		})
	}

	// Query /api/activity/lineage
	rLin := httptest.NewRequest(http.MethodGet, "/api/activity/lineage", nil)
	wLin := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wLin, rLin)

	if wLin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for lineage endpoint, got %d: %s", wLin.Code, wLin.Body.String())
	}

	var linResp struct {
		Count    int `json:"count"`
		Lineages []struct {
			LineageTree    string `json:"lineage_tree"`
			CurrentAgentID string `json:"current_agent_id"`
		} `json:"lineages"`
	}
	if err := json.Unmarshal(wLin.Body.Bytes(), &linResp); err != nil {
		t.Fatalf("failed to unmarshal lineage response: %v", err)
	}
	foundTree := false
	for _, l := range linResp.Lineages {
		if l.LineageTree == "root-orchestrator -> subagent-designer" {
			foundTree = true
			break
		}
	}
	if !foundTree {
		t.Fatalf("expected lineage tree 'root-orchestrator -> subagent-designer' in response, got %+v", linResp)
	}

	// Query /api/activity/topology
	rTop := httptest.NewRequest(http.MethodGet, "/api/activity/topology", nil)
	wTop := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wTop, rTop)

	if wTop.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for topology endpoint, got %d: %s", wTop.Code, wTop.Body.String())
	}
	if !strings.Contains(wTop.Body.String(), "subagent-designer") {
		t.Fatalf("expected subagent-designer in topology, got: %s", wTop.Body.String())
	}
}
