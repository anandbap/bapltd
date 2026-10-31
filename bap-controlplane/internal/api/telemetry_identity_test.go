package api

import (
	"bap-controlplane/internal/session"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGatewayCollectorCannotActAsWorkstation(t *testing.T) {
	s := setupTestServer()
	key := "synthetic-collector-credential-32-characters"
	if err := s.SetTelemetrySecurity(key); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/sessions/start", "/api/v1/sessions/heartbeat", "/api/v1/sessions/resume"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"session_id":"unknown","app_id":"fake","instance_id":"machine","client_pid":1}`))
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("collector gained lifecycle authority at %s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/v1/audit/ingest", strings.NewReader(`[{"event_id":"gateway","session_id":"unknown","source":"forged","decision":"deny"}]`))
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("collector refused: %s", w.Body.String())
	}
	if len(s.sessionStore.List(0)) != 0 {
		t.Fatal("gateway created an unknown live session")
	}
	if s.auditStore.List(1)[0].Source != "bap-gateway-pep" {
		t.Fatal("collector source was not canonicalized")
	}
	_, _ = s.sessionStore.Start(session.SessionStartRequest{SessionID: "known", AppID: "claude-code", InstanceID: "machine"})
	before, _ := s.sessionStore.GetSummary("known")
	r = httptest.NewRequest("POST", "/api/v1/audit/ingest", strings.NewReader(`[{"event_id":"gateway-known","session_id":"known","user_email":"forged","decision":"deny"}]`))
	r.Header.Set("Authorization", "Bearer "+key)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	after, _ := s.sessionStore.GetSummary("known")
	if w.Code != 200 || after.TotalEvents != before.TotalEvents || !after.LastActiveAt.Equal(before.LastActiveAt) {
		t.Fatal("collector impersonated owner or refreshed session presence")
	}
}
