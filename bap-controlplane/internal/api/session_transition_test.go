package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

// Regression: an older Claude session ending (or idling out) on the same workstation instance must not
// leave the newer session showing as stopped, and a reaped session that still heartbeats must recover.
func TestSessionTransition_OldSessionEndingDoesNotStopNewSession(t *testing.T) {
	s := setupTestServer()
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		// Both sessions run on the same workstation, so they share one instance identity.
		r.Header.Set("Authorization", "Bearer "+recoveryProof(t, s, "shared-ws"))
		s.Handler().ServeHTTP(w, r)
		return w
	}

	for _, id := range []string{"old-claude", "new-claude"} {
		if w := post("/api/v1/sessions/start", `{"session_id":"`+id+`","app_id":"claude-code","instance_id":"shared-ws"}`); w.Code != 200 {
			t.Fatalf("start %s: %d %s", id, w.Code, w.Body.String())
		}
	}

	// The old session times out while the new one is live but quiet (no heartbeat yet).
	if w := post("/api/v1/sessions/end", `{"session_id":"old-claude","reason":"idle_timeout"}`); w.Code != 200 {
		t.Fatalf("end old session: %d %s", w.Code, w.Body.String())
	}
	for _, a := range s.registry.List() {
		if a.InstanceID == "shared-ws" && a.Status != types.StatusActive {
			t.Fatalf("new session's agent presence was deregistered by the old session ending: %+v", a)
		}
	}
	if sess, err := s.sessionStore.Get("new-claude"); err != nil || sess.Status != "active" {
		t.Fatalf("new session should still be active: %+v %v", sess, err)
	}
}

func TestSessionTransition_IdleReapedSessionRecoversOnHeartbeat(t *testing.T) {
	s := setupTestServer()
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+recoveryProof(t, s, "reaped-claude"))
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := post("/api/v1/sessions/start", `{"session_id":"reaped-claude","app_id":"claude-code"}`); w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	// Idle reaper closes it with close_reason=idle_timeout.
	if n := s.sessionStore.PurgeStale(-time.Second); n != 1 {
		t.Fatalf("expected 1 session reaped, got %d", n)
	}

	w := post("/api/v1/sessions/heartbeat", `{"session_id":"reaped-claude"}`)
	if w.Code != 200 {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["action"] == "terminate" || resp["status"] == "closed" {
		t.Fatalf("a heartbeating idle-reaped session must not be told to terminate: %s", w.Body.String())
	}
	if sess, err := s.sessionStore.Get("reaped-claude"); err != nil || sess.Status != "active" {
		t.Fatalf("session should be resurrected by heartbeat: %+v %v", sess, err)
	}
}
