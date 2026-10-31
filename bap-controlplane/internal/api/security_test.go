package api

import (
	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGrantRequiresProofAndStopsAfterRevocation(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	pending, err := s.registry.PreRegister(types.PreRegisterRequest{AppID: "test", AgentName: "worker", PermittedScopes: []string{"api:read"}})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := s.registry.Enroll(pending.AgentID, "hash", "", "host", "linux", "amd64", "one")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.minter.Mint(agent, "hash", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(types.AcquireGrantRequest{AgentID: agent.AgentID, BinaryHash: "hash", Scopes: []string{"api:read"}})
	for _, tc := range []struct {
		token string
		want  int
	}{{"", 401}, {"forged", 401}, {token, 200}} {
		r := httptest.NewRequest("POST", "/api/v1/grants/acquire", bytes.NewReader(body))
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("grant status %d, want %d", w.Code, tc.want)
		}
	}
	if err := s.registry.Revoke(agent.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.consumeActiveGrant(token, "api:read"); err == nil {
		t.Fatal("already issued grant survived revocation")
	}
}

func TestPromptRedactionAcrossReadRoutes(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	_, err := s.sessionStore.Start(session.SessionStartRequest{
		SessionID: "private-session", AppID: "app", InstanceID: "private-instance",
		UserID: "private-user", UserEmail: "private@example.test", SPIFFEID: "spiffe://private",
		Hostname: "private-host", ClientPID: 987654, UserPrompt: "private prompt",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/inspector/data", "/api/v1/sessions", "/api/v1/sessions/private-session"} {
		for _, authenticated := range []bool{false, true} {
			r := httptest.NewRequest("GET", path, nil)
			r.RemoteAddr = "127.0.0.1:1234"
			if authenticated {
				r.Header.Set("Authorization", "Bearer test-admin")
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("%s: %d", path, w.Code)
			}
			for _, privateValue := range []string{"private prompt", "private-session", "private-instance", "private-user", "private@example.test", "spiffe://private", "private-host", "987654"} {
				if strings.Contains(w.Body.String(), privateValue) != authenticated {
					t.Fatalf("telemetry value %q visibility wrong at %s (authenticated=%v): %s", privateValue, path, authenticated, w.Body.String())
				}
			}
		}
	}
}

func TestAgentTargetRevokesLinkedSession(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	sess, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "sess-linked", AppID: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	agent := s.registry.EnsureSessionAgent(sess.AppID, sess.SessionID, "", "", "")
	body := bytes.NewBufferString(`{"target":"` + agent.AgentID + `","action":"revoke"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/control/agent/kill", body)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer test-admin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d %s", w.Code, w.Body.String())
	}
	if !s.sessionStore.IsRevoked(sess.SessionID) {
		t.Fatal("registry agent changed state but linked session authority was not revoked")
	}
	if !strings.Contains(w.Body.String(), "workload process was not terminated") {
		t.Fatalf("response did not explain revoke semantics: %s", w.Body.String())
	}
}

func TestPromptTelemetryAcceptsOnlyLifecycleHookProducer(t *testing.T) {
	s := setupTestServer()
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "sess-prompt", AppID: "claude-code",InstanceID:"prompt-machine"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"session_id":"sess-prompt","user_prompt":"hello"}`, http.StatusBadRequest},
		{`{"session_id":"sess-prompt","user_prompt":"hello","producer":"claude-lifecycle-hook","prompt_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prompt_capture_enabled":true,"intent":{"primary":"UNKNOWN","confidence":0,"classifier_version":"bap-intent-rules-v1","source":"claude-user-prompt-submit","evidence":["no-rule-match"]}}`, http.StatusOK},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/prompt", strings.NewReader(tc.body))
		r.Header.Set("Authorization","Bearer "+recoveryProof(t,s,"prompt-machine"))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("prompt status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
		}
	}
	events := s.auditStore.List(10)
	if len(events) != 1 || events[0].UserPrompt != "hello" || events[0].FullCommand != "USER_PROMPT_SUBMITTED" || events[0].PrimaryIntent != "UNKNOWN" {
		t.Fatalf("expected exactly one prompt event, got %#v", events)
	}
}

func TestPromptTelemetryAllowsIntentWithoutRawPrompt(t *testing.T) {
	s := setupTestServer()
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "sess-private-intent", AppID: "claude-code",InstanceID:"prompt-machine"})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"session_id":"sess-private-intent","producer":"claude-lifecycle-hook","prompt_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","prompt_capture_enabled":false,"intent":{"primary":"BUG_FIX","secondary":["DATABASE_CHANGE"],"tags":["DATABASE"],"confidence":0.98,"classifier_version":"bap-intent-rules-v1","source":"claude-user-prompt-submit"}}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/prompt", strings.NewReader(body))
	r.Header.Set("Authorization","Bearer "+recoveryProof(t,s,"prompt-machine"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("prompt status = %d: %s", w.Code, w.Body.String())
	}
	got, err := s.sessionStore.Get("sess-private-intent")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserPrompt != "" || got.Intent.Primary != "BUG_FIX" || len(got.Intent.Secondary) != 1 || got.Intent.Secondary[0] != "DATABASE_CHANGE" || got.Intent.PromptCaptured {
		t.Fatalf("unexpected private intent session: %#v", got)
	}
}

func TestRevokedSessionCannotSelfRestore(t *testing.T) {
	s := setupTestServer()
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "sess-a", AppID: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.sessionStore.RevokeTarget("sess", "test"); err == nil {
		t.Fatal("prefix matched a session")
	}
	if _, err := s.sessionStore.RevokeTarget("sess-a", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.sessionStore.End("sess-a", "client exit"); err == nil {
		t.Fatal("client removed revocation by ending session")
	}
	if _, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "sess-a", AppID: "app"}); err == nil {
		t.Fatal("client self-restored revoked session")
	}
}

func TestNoAmbientAdminAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, path, method, body, header, cookie string
		want                                     int
	}{
		{"local_handshake", "/api/v1/auth/inspector-handshake", "GET", "", "", "", 401},
		{"local_empty_login", "/api/v1/auth/admin-login", "POST", `{}`, "", "", 401},
		{"cookie_login", "/api/v1/auth/admin-login", "POST", `{}`, "", "test-admin", 401},
		{"cookie_mutation", "/api/v1/control/kill-switch", "POST", `{"enabled":true}`, "", "test-admin", 401},
		{"valid_handshake", "/api/v1/auth/inspector-handshake", "GET", "", "test-admin", "", 200},
		{"valid_login", "/api/v1/auth/admin-login", "POST", `{"token":"test-admin"}`, "", "", 200},
		{"invalid_login", "/api/v1/auth/admin-login", "POST", `{"token":"wrong"}`, "", "", 403},
		{"malformed_login", "/api/v1/auth/admin-login", "POST", `{`, "", "", 400},
		{"trailing_login", "/api/v1/auth/admin-login", "POST", `{"token":"test-admin"}{}`, "", "", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := setupTestServer()
			s.SetAdminSecurity("test-admin", false)
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.RemoteAddr = "127.0.0.1:1234"
			if tc.header != "" {
				r.Header.Set("Authorization", "Bearer "+tc.header)
			}
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "bap_admin_token", Value: tc.cookie})
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "test-admin") || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("credential disclosed or cookie issued")
			}
			if s.policyStore.GetBundle().KillSwitch {
				t.Fatal("unauthenticated request mutated state")
			}
		})
	}
}

func TestBrowserOrigins(t *testing.T) {
	for _, tc := range []struct {
		name, origin, method string
		want                 int
	}{
		{"same_origin", "http://example.com", "GET", 200},
		{"allowed", "https://dashboard.example.test", "GET", 200},
		{"preflight", "https://dashboard.example.test", "OPTIONS", 204},
		{"unapproved", "https://evil.example.test", "GET", 403},
		{"unapproved_preflight", "https://evil.example.test", "OPTIONS", 403},
		{"null", "null", "GET", 403},
		{"native_client", "", "GET", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := setupTestServer()
			if err := s.SetAllowedOrigins([]string{"https://dashboard.example.test"}); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(tc.method, "http://example.com/api/v1/health", nil)
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d", w.Code, tc.want)
			}
			if tc.want == 403 && w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unapproved origin reflected")
			}
			if w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("ambient credentials enabled")
			}
		})
	}
	for _, origin := range []string{"*", "null", "https://example.test/", "https://user@example.test", "https://example.test?x=1"} {
		if err := setupTestServer().SetAllowedOrigins([]string{origin}); err == nil {
			t.Fatalf("invalid origin accepted: %s", origin)
		}
	}
}

func TestInvalidControlPayloadDoesNotRestoreFleet(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	s.policyStore.SetKillSwitch(true)
	for _, body := range []string{`{}`, `{"enabled":null}`, `{`} {
		r := httptest.NewRequest("POST", "/api/v1/control/kill-switch", bytes.NewBufferString(body))
		r.Header.Set("Authorization", "Bearer test-admin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 || !s.policyStore.GetBundle().KillSwitch {
			t.Fatalf("invalid body changed state: %s", body)
		}
	}
}

func TestUnconfiguredAdminFailsClosed(t *testing.T) {
	s := setupTestServer()
	r := httptest.NewRequest("POST", "/api/v1/control/kill-switch", strings.NewReader(`{"enabled":true}`))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 503 || s.policyStore.GetBundle().KillSwitch {
		t.Fatal("unconfigured admin allowed mutation")
	}
}

func TestEnrollmentCodeCreationRequiresAdmin(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	r := httptest.NewRequest("POST", "/api/v1/agents/pre-register", strings.NewReader(`{"app_id":"test","agent_name":"test"}`))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 || len(s.registry.List()) != 0 {
		t.Fatal("anonymous enrollment-code creation allowed")
	}
}
