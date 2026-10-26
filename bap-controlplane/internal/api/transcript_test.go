package api

import (
	"bap-controlplane/internal/audit"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func transcriptText(t *testing.T, s *Server, configure func(*http.Request)) (text string, unlocked bool) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/sessions/transcript?session_id=sess-t", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	if configure != nil {
		configure(r)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Unlocked bool `json:"unlocked"`
		Items    []struct {
			Text string `json:"text"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Items) != 1 {
		t.Fatalf("bad body: %v %s", err, w.Body.String())
	}
	return out.Items[0].Text, out.Unlocked
}

func seedTranscript(t *testing.T, s *Server) {
	t.Helper()
	if _, err := s.auditStore.Ingest([]audit.Event{{
		EventID: "ev-t1", SessionID: "sess-t", Source: "claude-code", Executable: "user_prompt",
		FullCommand: "USER_PROMPT_SUBMITTED", Decision: "intent", UserPrompt: "secret prompt text", PromptCaptured: true,
	}}); err != nil {
		t.Fatal(err)
	}
}

// Admin view must only turn on when a valid token is presented, never by default and never
// because the caller is on loopback or because no token is configured.
func TestTranscriptUnlocksOnlyWithAdminToken(t *testing.T) {
	// A token is configured: loopback alone does not unlock.
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	seedTranscript(t, s)
	if text, unlocked := transcriptText(t, s, nil); unlocked || text == "secret prompt text" {
		t.Fatalf("unauthenticated loopback viewer must be locked, got unlocked=%v text=%q", unlocked, text)
	}
	if _, unlocked := transcriptText(t, s, func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }); unlocked {
		t.Fatal("wrong token must not unlock")
	}
	if text, unlocked := transcriptText(t, s, func(r *http.Request) { r.Header.Set("Authorization", "Bearer test-admin") }); !unlocked || text != "secret prompt text" {
		t.Fatalf("valid token must unlock, got unlocked=%v text=%q", unlocked, text)
	}
	if _, unlocked := transcriptText(t, s, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "bap_admin_token", Value: "test-admin"}) }); !unlocked {
		t.Fatal("dashboard cookie token must unlock")
	}

	// No token configured: still locked, since there is nothing to enter.
	open := setupTestServer()
	seedTranscript(t, open)
	if text, unlocked := transcriptText(t, open, nil); unlocked || text == "secret prompt text" {
		t.Fatalf("no configured token must not mean admin, got unlocked=%v text=%q", unlocked, text)
	}
}
