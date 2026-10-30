package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

func TestSessionFreezeIsIndependentOfWorkstationAndOtherSessions(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	host := s.registry.EnsureSessionAgent("bapedge", "workstation", "", "", "host")
	for _, id := range []string{"one", "two"} {
		if _, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: id, AppID: "claude-code", InstanceID: "workstation"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{"freeze", "unfreeze"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/control/agent/kill", strings.NewReader(`{"target":"one","scope":"session","action":"`+action+`"}`))
		r.Header.Set("X-BAP-Admin-Token", "test-admin")
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
		}
		if s.sessionStore.IsRevoked("one") != (action == "freeze") {
			t.Fatalf("unexpected session state after %s", action)
		}
		if s.sessionStore.IsRevoked("two") {
			t.Fatal("sibling session was revoked")
		}
		agent, _ := s.registry.Get(host.AgentID)
		if agent.Status != types.StatusActive {
			t.Fatal("session action quarantined workstation")
		}
	}
}

func TestWorkstationUnfreezeRestoresInsteadOfQuarantining(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	agent := s.registry.EnsureSessionAgent("bapedge", "workstation", "", "", "host")
	for _, action := range []string{"freeze", "unfreeze"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/control/quarantine", strings.NewReader(`{"target":"`+agent.AgentID+`","action":"`+action+`"}`))
		r.Header.Set("X-BAP-Admin-Token", "test-admin")
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
		}
		got, _ := s.registry.Get(agent.AgentID)
		want := types.StatusActive
		if action == "freeze" {
			want = types.StatusQuarantined
		}
		if got.Status != want {
			t.Fatalf("%s: got %s, want %s", action, got.Status, want)
		}
	}
}

func TestLiveSessionUsesLatestDecisionRatherThanAllow(t *testing.T) {
	s := setupTestServer()
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "decisions", AppID: "claude-code", UserPrompt: "test prompt"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/activity/live", nil))
		var result struct {
			Activities []types.AgentActivityEvent `json:"activities"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Activities) != 1 || result.Activities[0].PolicyDecision != want {
			t.Fatalf("want %s: %s", want, w.Body.String())
		}
	}
	check("UNKNOWN")
	now := time.Now().UTC()
	s.sessionStore.RecordEvent("decisions", audit.Event{Decision: "allow", Timestamp: now.Format(time.RFC3339Nano)})
	check("ALLOW")
	s.sessionStore.RecordEvent("decisions", audit.Event{Decision: "deny", FullCommand: "blocked operation", Timestamp: now.Add(time.Second).Format(time.RFC3339Nano)})
	check("DENY")
	s.sessionStore.RecordEvent("decisions", audit.Event{Decision: "allow", Timestamp: now.Add(-time.Second).Format(time.RFC3339Nano)})
	check("DENY")
}

func TestNewPromptDoesNotInheritPreviousAllow(t *testing.T) {
	s := setupTestServer()
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "new-prompt", AppID: "claude-code", UserPrompt: "first"})
	if err != nil {
		t.Fatal(err)
	}
	s.sessionStore.RecordEvent("new-prompt", audit.Event{Decision: "allow", Timestamp: time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)})
	_, err = s.sessionStore.SetPromptAndIntent("new-prompt", "second", session.IntentContext{})
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := s.sessionStore.Get("new-prompt")
	if got := s.sessionToActivityEvent(sess).PolicyDecision; got != "UNKNOWN" {
		t.Fatalf("new prompt inherited %s", got)
	}
}

func TestFreezeRequiresAdminAndExplicitScope(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "protected", AppID: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ body, token string }{
		{`{"target":"protected","scope":"session","action":"freeze"}`, ""},
		{`{"target":"protected","action":"freeze"}`, "test-admin"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/control/agent/kill", strings.NewReader(tc.body))
		r.Header.Set("X-BAP-Admin-Token", tc.token)
		s.Handler().ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatalf("invalid freeze accepted: %s", tc.body)
		}
		if s.sessionStore.IsRevoked("protected") {
			t.Fatal("rejected request mutated session")
		}
	}
}
