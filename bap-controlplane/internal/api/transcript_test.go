package api

import (
	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/session"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestTranscriptCallsFormatIncludesAllowedBlockedAndNarrowed(t *testing.T) {
	s := setupTestServer()
	if _, err := s.auditStore.Ingest([]audit.Event{
		{
			EventID: "ev-c1", SessionID: "sess-calls", Source: "claude-code", Executable: "powershell",
			FullCommand: "whoami", Decision: "deny", Reason: "ZeroStandingPrivilegeViolation: no grant",
		},
		{
			EventID: "ev-c2", SessionID: "sess-calls", Source: "claude-code", Executable: "bapedge",
			FullCommand: "bapedge zsp authorize --actions repo:*", Decision: "allow",
			GrantID: "grant-narrow-1", NarrowingApplied: true,
			NarrowingReason: "Monotonic scope attenuation: [repo:*] -> [repo:read, repo:push]",
			RequestedActions: []string{"repo:*"}, AllowedActions: []string{"repo:read", "repo:push"},
			ZSPConcept: "ZSP_SCOPE_NARROWED",
		},
	}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/api/v1/sessions/transcript?session_id=sess-calls&format=calls", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var res struct {
		AllowedCount   int            `json:"allowed_count"`
		BlockedCount   int            `json:"blocked_count"`
		NarrowedCount  int            `json:"narrowed_count"`
		ZSPConcepts    map[string]int `json:"zsp_concepts"`
		AllowedCalls   []any          `json:"allowed_calls"`
		BlockedCalls   []any          `json:"blocked_calls"`
		NarrowedGrants []any          `json:"narrowed_grants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal failed: %v\n%s", err, w.Body.String())
	}
	if res.AllowedCount != 1 || res.BlockedCount != 1 || res.NarrowedCount != 1 {
		t.Fatalf("unexpected counts: %+v", res)
	}
	if res.ZSPConcepts["ZSP_DENY_NO_GRANT"] != 1 || res.ZSPConcepts["ZSP_SCOPE_NARROWED"] != 1 {
		t.Fatalf("unexpected zsp_concepts: %+v", res.ZSPConcepts)
	}
}

func TestSessionToActivityEventPreservesNarrowingAcrossLaterPrompts(t *testing.T) {
	s := &Server{}
	t1 := time.Now().UTC().Add(-2 * time.Minute)
	t2 := t1.Add(30 * time.Second)
	t3 := t2.Add(30 * time.Second)

	sess := &session.Session{
		SessionID:    "sess-multi-10",
		AppID:        "claude-code",
		Status:       "active",
		LastActiveAt: t3,
		UserPrompt:   "Scenario 10 prompt",
		Intent:       session.IntentContext{Primary: "CODE_INSPECTION", PromptHash: "hash-10"},
		Events: []audit.Event{
			{
				EventID:          "ev-narrow",
				SessionID:        "sess-multi-10",
				Timestamp:        t1.Format(time.RFC3339Nano),
				Decision:         "allow",
				PromptHash:       "hash-3",
				FullCommand:      "bapedge zsp authorize --actions repo:* [NARROWED -> repo:read,repo:push]",
				GrantID:          "grant-n1",
				NarrowingApplied: true,
				NarrowingReason:  "Monotonic scope attenuation: [repo:*] -> [repo:read repo:push]",
				RequestedActions: []string{"repo:*"},
				AllowedActions:   []string{"repo:read", "repo:push"},
				ZSPConcept:       "ZSP_SCOPE_NARROWED",
			},
			{
				EventID:     "ev-p10",
				SessionID:   "sess-multi-10",
				Timestamp:   t2.Format(time.RFC3339Nano),
				FullCommand: "USER_PROMPT_SUBMITTED",
				UserPrompt:  "Scenario 10 prompt",
			},
			{
				EventID:     "ev-deny",
				SessionID:   "sess-multi-10",
				Timestamp:   t3.Format(time.RFC3339Nano),
				Decision:    "deny",
				PromptHash:  "hash-10",
				FullCommand: "curl https://example.com",
			},
		},
	}

	act := s.sessionToActivityEvent(sess)
	if !act.NarrowingApplied {
		t.Fatalf("expected NarrowingApplied=true to be preserved across later prompts, got false (outcome=%s)", act.OutcomeCategory)
	}
	if len(act.AllowedActions) != 2 || act.GrantID != "grant-n1" {
		t.Fatalf("expected narrowing metadata preserved, got grant=%q allowed=%v", act.GrantID, act.AllowedActions)
	}
}
