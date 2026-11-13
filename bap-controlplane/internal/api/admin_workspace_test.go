package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"bap-controlplane/internal/hitl"
)

func adminWorkspaceRequest(s *Server, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestApprovalInboxRequiresAdminAndRecordsOneDecision(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	request, err := s.escalationMgr.RequestEscalation("task", "session", "agent", "workspace/data", "fs:write", "Update report")
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"escalation_id":%q,"decision":"approve","reviewer_email":"reviewer@example.test","ttl_seconds":60}`, request.EscalationID)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/escalation/requests", ""},
		{"POST", "/api/v1/escalation/resolve", body},
		{"POST", "/api/v1/policies/cedar/simulate", `{"draft_policy":"permit(principal, action, resource);","include_historical_audit":true}`},
	} {
		if w := adminWorkspaceRequest(s, tc.method, tc.path, tc.body, ""); w.Code != 401 {
			t.Fatalf("unauthenticated %s: %d %s", tc.path, w.Code, w.Body.String())
		}
		if w := adminWorkspaceRequest(s, tc.method, tc.path, tc.body, "forged"); w.Code != 403 {
			t.Fatalf("invalid credential %s: %d", tc.path, w.Code)
		}
	}
	if request.Status != hitl.StatusPending {
		t.Fatal("unauthenticated request changed the approval")
	}
	if w := adminWorkspaceRequest(s, "GET", "/api/v1/escalation/requests", "", "test-admin"); w.Code != 200 || !strings.Contains(w.Body.String(), request.EscalationID) {
		t.Fatalf("inbox: %d %s", w.Code, w.Body.String())
	}
	for _, badBody := range []string{
		strings.Replace(body, `"approve"`, `"typo"`, 1),
		strings.Replace(body, `"ttl_seconds":60`, `"ttl_seconds":901`, 1),
		strings.Replace(body, `"reviewer@example.test"`, `""`, 1),
	} {
		if w := adminWorkspaceRequest(s, "POST", "/api/v1/escalation/resolve", badBody, "test-admin"); w.Code != 400 {
			t.Fatalf("invalid decision: %d %s", w.Code, w.Body.String())
		}
	}
	w := adminWorkspaceRequest(s, "POST", "/api/v1/escalation/resolve", body, "test-admin")
	if w.Code != 200 || request.Status != hitl.StatusApproved || request.ReviewerEmail != "reviewer@example.test" {
		t.Fatalf("decision: %d %s", w.Code, w.Body.String())
	}
	if w := adminWorkspaceRequest(s, "POST", "/api/v1/escalation/resolve", body, "test-admin"); w.Code != 409 {
		t.Fatalf("duplicate decision: %d", w.Code)
	}
}

func TestPolicyDeployRejectsStaleEditorWithoutOverwritingFreeze(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	initial := s.policyStore.GetBundle()
	s.policyStore.SetKillSwitch(true)
	payload := map[string]any{"policy_cedar": "permit(principal, action, resource);", "reason": "reviewed change", "expected_version": initial.Version, "kill_switch": false}
	body, _ := json.Marshal(payload)
	w := adminWorkspaceRequest(s, "POST", "/api/v1/policies/cedar/deploy", string(body), "test-admin")
	if w.Code != 409 {
		t.Fatalf("stale editor: %d %s", w.Code, w.Body.String())
	}
	if !s.policyStore.GetBundle().KillSwitch {
		t.Fatal("stale editor cleared fleet freeze")
	}
	current := s.policyStore.GetBundle()
	payload["expected_version"] = current.Version
	payload["kill_switch"] = true
	body, _ = json.Marshal(payload)
	w = adminWorkspaceRequest(s, "POST", "/api/v1/policies/cedar/deploy", string(body), "test-admin")
	if w.Code != 200 {
		t.Fatalf("reviewed policy: %d %s", w.Code, w.Body.String())
	}
	if got := s.policyStore.GetBundle(); got.Version <= current.Version || !got.KillSwitch {
		t.Fatalf("deployment lost freeze/version: %+v", got)
	}
}
