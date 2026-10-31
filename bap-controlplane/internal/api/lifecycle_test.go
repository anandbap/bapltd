package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"bap-controlplane/internal/registry"
	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

func TestControlPlaneHostsConsolidatedDashboard(t *testing.T) {
	s := setupTestServer()
	root := httptest.NewRecorder()
	s.Handler().ServeHTTP(root, httptest.NewRequest("GET", "/", nil))
	if root.Code != 200 || !strings.Contains(root.Body.String(), "/dashboard/") {
		t.Fatalf("unexpected control-plane root response: %d %s", root.Code, root.Body.String())
	}

	dashboard := httptest.NewRecorder()
	s.Handler().ServeHTTP(dashboard, httptest.NewRequest("GET", "/dashboard/", nil))
	if dashboard.Code != 200 {
		t.Fatalf("control plane failed to host dashboard: status %d", dashboard.Code)
	}
}

func TestOverlappingSessionsHaveIndependentPresence(t *testing.T) {
	s := setupTestServer()
	postJSON := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		var identity struct { SessionID string `json:"session_id"` };_=json.Unmarshal([]byte(body),&identity)
		r.Header.Set("Authorization","Bearer "+recoveryProof(t,s,identity.SessionID))
		s.Handler().ServeHTTP(w, r)
		return w
	}

	for _, id := range []string{"session-one", "session-two"} {
		if w := postJSON("/api/v1/sessions/start", `{"session_id":"`+id+`","app_id":"claude-code"}`); w.Code != 200 {
			t.Fatalf("start %s: %d %s", id, w.Code, w.Body.String())
		}
	}
	agents := s.registry.List()
	if len(agents) != 2 || agents[0].InstanceID == agents[1].InstanceID {
		t.Fatalf("sessions collapsed into a shared registry identity: %+v", agents)
	}

	if w := postJSON("/api/v1/sessions/end", `{"session_id":"session-one"}`); w.Code != 200 {
		t.Fatalf("end first session: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON("/api/v1/sessions/heartbeat", `{"session_id":"session-two"}`); w.Code != 200 {
		t.Fatalf("heartbeat second session: %d %s", w.Code, w.Body.String())
	}
	for _, agent := range s.registry.List() {
		if agent.InstanceID == "session-two" && agent.Status != types.StatusActive {
			t.Fatalf("session-two should remain active after session-one end: %+v", agent)
		}
		if agent.InstanceID == "session-one" && agent.Status != "deregistered" {
			t.Fatalf("session-one should be deregistered after shutdown: %+v", agent)
		}
	}
}

func TestInspectorReadDoesNotExpireSessions(t *testing.T) {
	s := setupTestServer()
	if _, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "read-only-session", AppID: "test"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BAP_SESSION_TIMEOUT", "1ns")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/inspector/data", nil))
	if w.Code != 200 {
		t.Fatalf("inspector response: %d", w.Code)
	}
	sess, err := s.sessionStore.Get("read-only-session")
	if err != nil || sess.Status != "active" {
		t.Fatalf("GET mutated session lifecycle: %+v %v", sess, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatRehydratesRegistryAfterRestart(t *testing.T) {
	s := setupTestServer()
	if _, err := s.sessionStore.Start(session.SessionStartRequest{
		SessionID: "surviving-session",
		InstanceID: "surviving-session",
		AppID:     "claude-code",
		Hostname:  "developer-host",
	}); err != nil {
		t.Fatal(err)
	}
	// Model a process restart: SQLite-backed sessions survive but the registry
	// starts empty.
	s.registry = registry.NewStore("bap.internal")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/sessions/heartbeat", strings.NewReader(`{"session_id":"surviving-session"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization","Bearer "+recoveryProof(t,s,"surviving-session"))
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("heartbeat after restart: %d %s", w.Code, w.Body.String())
	}
	agents := s.registry.List()
	if len(agents) != 1 || agents[0].InstanceID != "surviving-session" || agents[0].Status != types.StatusActive {
		t.Fatalf("registry was not rehydrated from live session: %+v", agents)
	}
}

func TestRevokedSessionHeartbeatAndPromptBlock(t *testing.T) {
	s := setupTestServer()

	// 1. Start session
	if _, err := s.sessionStore.Start(session.SessionStartRequest{
		SessionID: "sess-rev-test",
		InstanceID: "sess-rev-test",
		AppID:     "claude-code",
		Hostname:  "test-host",
	}); err != nil {
		t.Fatal(err)
	}

	// 2. Active heartbeat should succeed with status alive
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/sessions/heartbeat", strings.NewReader(`{"session_id":"sess-rev-test"}`))
	r.Header.Set("Authorization","Bearer "+recoveryProof(t,s,"sess-rev-test"))
	r.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"alive"`) {
		t.Fatalf("expected alive heartbeat, got: %d %s", w.Code, w.Body.String())
	}

	// 3. Revoke session
	if err := s.sessionStore.RevokeSession("sess-rev-test", "Admin CISO kill-switch test"); err != nil {
		t.Fatal(err)
	}

	// 4. Heartbeat should now report status revoked and action terminate
	wRev := httptest.NewRecorder()
	rRev := httptest.NewRequest("POST", "/api/v1/sessions/heartbeat", strings.NewReader(`{"session_id":"sess-rev-test"}`))
	rRev.Header.Set("Authorization","Bearer "+recoveryProof(t,s,"sess-rev-test"))
	rRev.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(wRev, rRev)
	if wRev.Code != 200 || !strings.Contains(wRev.Body.String(), `"status":"revoked"`) || !strings.Contains(wRev.Body.String(), `"action":"terminate"`) {
		t.Fatalf("expected revoked status in heartbeat, got: %d %s", wRev.Code, wRev.Body.String())
	}

	// 5. Subsequent prompt telemetry should be rejected with HTTP 403
	wPrompt := httptest.NewRecorder()
	rPrompt := httptest.NewRequest("POST", "/api/v1/sessions/prompt", strings.NewReader(`{"session_id":"sess-rev-test","user_prompt":"run unauthorized task","producer":"claude-lifecycle-hook","prompt_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","prompt_capture_enabled":true,"intent":{"primary":"UNKNOWN","confidence":0,"classifier_version":"bap-intent-rules-v1","source":"claude-user-prompt-submit"}}`))
	rPrompt.Header.Set("Content-Type", "application/json")
	rPrompt.Header.Set("Authorization","Bearer "+recoveryProof(t,s,"sess-rev-test"))
	s.Handler().ServeHTTP(wPrompt, rPrompt)
	if wPrompt.Code != 403 {
		t.Fatalf("expected HTTP 403 Forbidden for revoked prompt, got: %d %s", wPrompt.Code, wPrompt.Body.String())
	}
}
