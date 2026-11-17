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

func TestSimulatedEndpointsAreDemoOnlyAndAdminOnly(t *testing.T) {
	paths := []string{
		"/api/v1/spiffe/issue-svid",
		"/api/v1/spiffe/validate",
		"/api/v1/attestation/tpm-quote",
		"/api/v1/sandbox/landlock/check",
		"/api/v1/sandbox/ebpf/execve",
	}

	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	for _, p := range paths {
		if w := authSurfaceRequest(s,http.MethodPost, p, "test-admin"); w.Code != http.StatusNotFound {
			t.Fatalf("POST %s outside demo mode = %d, want 404 (not served)", p, w.Code)
		}
	}

	s.SetDemoMode(true)
	for _, p := range paths {
		if w := authSurfaceRequest(s,http.MethodPost, p, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("POST %s in demo mode without credential = %d, want 401", p, w.Code)
		}
		// A handler may itself answer 403 (the TPM verifier rejects an empty quote), so only 401
		// (auth failed) and 404 (not served) prove the request did not reach the handler.
		if w := authSurfaceRequest(s, http.MethodPost, p, "test-admin"); w.Code == http.StatusUnauthorized || w.Code == http.StatusNotFound {
			t.Fatalf("POST %s in demo mode with admin credential = %d, want it to reach the handler", p, w.Code)
		}
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
		{"/api/activity/stream?token=secret", "secret"},
		{"/api/activity/stream?admin_token=secret", "secret"},
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
