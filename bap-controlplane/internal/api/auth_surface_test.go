package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// BAP-1098: control-plane read surface, simulated endpoints, URL credentials, auth throttling.

func authSurfaceRequest(s *Server, method, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	r.RemoteAddr = "127.0.0.1:4321"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// serveAsAdmin serves a request through the full handler with the test administrator credential,
// for tests of routes that now require admin authentication.
func serveAsAdmin(s *Server, w http.ResponseWriter, r *http.Request) {
	s.SetAdminSecurity("test-admin", true)
	if r.Header.Get("X-BAP-Admin-Token") == "" && r.Header.Get("Authorization") == "" {
		r.Header.Set("X-BAP-Admin-Token", "test-admin")
	}
	s.Handler().ServeHTTP(w, r)
}

func TestSensitiveReadRoutesRequireAdmin(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	for _, path := range []string{
		"/api/v1/audit/export/siem",
		"/api/v1/audit/export/siem?format=cef",
		"/api/v1/audit/notarizations",
		"/api/v1/audit/worm/manifests",
	} {
		if w := authSurfaceRequest(s,http.MethodGet, path, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without credential = %d, want 401", path, w.Code)
		}
		if w := authSurfaceRequest(s,http.MethodGet, path, "wrong"); w.Code != http.StatusForbidden {
			t.Fatalf("GET %s with wrong credential = %d, want 403", path, w.Code)
		}
		if w := authSurfaceRequest(s,http.MethodGet, path, "test-admin"); w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
			t.Fatalf("GET %s with admin credential = %d, want it to reach the handler", path, w.Code)
		}
	}
}

func TestTelemetryReadRoutesRequireAdmin(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	for _, path := range []string{
		"/api/v1/agents",
		"/api/v1/sessions",
		"/api/v1/audit/events",
		"/api/v1/audit/risky-events",
		"/api/v1/inspector/data",
		"/api/v1/sts/tokens",
		"/api/activity/live",
		"/api/v1/activity/summary",
		"/api/v1/activity/stream",
	} {
		if w := authSurfaceRequest(s, http.MethodGet, path, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without credential = %d, want 401", path, w.Code)
		}
		// Streams may carry the token in the URL (EventSource); invoking one with a valid token would block.
		if strings.HasSuffix(path, "/stream") {
			continue
		}
		if w := authSurfaceRequest(s, http.MethodGet, path+"?token=test-admin", ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s with URL token = %d, want 401", path, w.Code)
		}
	}
}

// The simulated SPIFFE/TPM/Landlock/eBPF endpoints and the simulated OAuth login pages were removed;
// they must not be served in any mode, even to an administrator or in demo mode.
func TestRemovedSimulationEndpointsAreNotServed(t *testing.T) {
	paths := []string{
		"/api/v1/spiffe/issue-svid",
		"/api/v1/spiffe/validate",
		"/api/v1/attestation/tpm-quote",
		"/api/v1/sandbox/landlock/check",
		"/api/v1/sandbox/ebpf/execve",
		"/api/v1/auth/oauth/google-login",
		"/api/v1/auth/oauth/github-login",
	}

	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	s.SetDemoMode(true)
	for _, p := range paths {
		for _, token := range []string{"", "test-admin"} {
			if w := authSurfaceRequest(s, http.MethodPost, p, token); w.Code != http.StatusNotFound {
				t.Fatalf("POST %s = %d, want 404 (endpoint removed)", p, w.Code)
			}
		}
	}
}

func TestStreamTicketIsSingleUseAndShortLived(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)

	if w := authSurfaceRequest(s, http.MethodPost, "/api/v1/auth/stream-ticket", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("ticket without credential = %d, want 401", w.Code)
	}
	w := authSurfaceRequest(s, http.MethodPost, "/api/v1/auth/stream-ticket", "test-admin")
	if w.Code != http.StatusOK {
		t.Fatalf("ticket with admin credential = %d: %s", w.Code, w.Body.String())
	}
	ticket := strings.TrimSpace(w.Body.String())
	start := strings.Index(ticket, "bap_stk_")
	if start < 0 {
		t.Fatalf("no ticket in response: %s", ticket)
	}
	ticket = ticket[start : start+len("bap_stk_")+32]

	if !streamTickets.consume(ticket) {
		t.Fatal("fresh ticket was rejected")
	}
	if streamTickets.consume(ticket) {
		t.Fatal("ticket must be single-use")
	}
	if streamTickets.consume("bap_stk_forged") {
		t.Fatal("forged ticket accepted")
	}

	now := time.Now()
	streamTickets.now = func() time.Time { return now }
	t.Cleanup(func() { streamTickets.now = time.Now })
	expiring, err := streamTickets.issue()
	if err != nil {
		t.Fatal(err)
	}
	streamTickets.now = func() time.Time { return now.Add(streamTicketTTL + time.Second) }
	if streamTickets.consume(expiring) {
		t.Fatal("expired ticket accepted")
	}

	// A forged ticket on a stream is rejected without reaching the handler.
	if w := authSurfaceRequest(s, http.MethodGet, "/api/activity/stream?ticket=bap_stk_forged", ""); w.Code != http.StatusForbidden {
		t.Fatalf("forged stream ticket = %d, want 403", w.Code)
	}
}

func TestAdminCredentialInURLOnlyAcceptedOnStreams(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"/api/v1/inspector/data?token=secret", ""},
		{"/api/v1/sessions?admin_token=secret", ""},
		{"/api/v1/audit/events?token=secret", ""},
		{"/api/activity/stream?token=secret", ""},
		{"/api/activity/stream?admin_token=secret", ""},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, tc.url, nil)
		if got := telemetryViewerCredential(r); got != tc.want {
			t.Fatalf("credential from %s = %q, want %q", tc.url, got, tc.want)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/inspector/data", nil)
	r.Header.Set("Authorization", "Bearer from-header")
	if got := telemetryViewerCredential(r); got != "from-header" {
		t.Fatalf("header credential = %q, want from-header", got)
	}
}

func TestAuthFailureThrottleWindowAndReset(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	th := newAuthFailureThrottle(3, time.Minute)
	th.now = func() time.Time { return now }

	for i := 1; i <= 3; i++ {
		if over, _ := th.recordFailure("10.0.0.1"); over {
			t.Fatalf("failure %d should not be over the limit", i)
		}
	}
	over, retry := th.recordFailure("10.0.0.1")
	if !over || retry <= 0 || retry > time.Minute {
		t.Fatalf("4th failure: over=%v retry=%v, want over with retry in (0,1m]", over, retry)
	}
	if over, _ := th.recordFailure("10.0.0.2"); over {
		t.Fatal("a different client must have its own budget")
	}

	now = now.Add(2 * time.Minute)
	if over, _ := th.recordFailure("10.0.0.1"); over {
		t.Fatal("budget should reset after the window")
	}

	th.recordFailure("10.0.0.3")
	th.reset("10.0.0.3")
	if th.clients["10.0.0.3"] != nil {
		t.Fatal("reset should clear the client's failure history")
	}
}

func TestInvalidAdminCredentialsAreThrottledButValidOneIsNot(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)

	sawThrottle := false
	for i := 0; i < 15; i++ {
		w := authSurfaceRequest(s,http.MethodGet, "/api/v1/audit/notarizations", "guess-"+string(rune('a'+i)))
		if w.Code == http.StatusTooManyRequests {
			sawThrottle = true
			if w.Header().Get("Retry-After") == "" {
				t.Fatal("429 must carry Retry-After")
			}
		}
	}
	if !sawThrottle {
		t.Fatal("15 invalid credentials from one address were never throttled")
	}

	// The real administrator is never locked out, even from the throttled address.
	if w := authSurfaceRequest(s,http.MethodGet, "/api/v1/audit/notarizations", "test-admin"); w.Code == http.StatusTooManyRequests || w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("valid credential rejected while throttled: %d", w.Code)
	}
}
