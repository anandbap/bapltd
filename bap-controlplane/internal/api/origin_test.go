package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/otc"
	"bap-controlplane/internal/registry"
)

func originServer() *Server {
	return NewServer(registry.NewStore("bap.internal"), otc.NewStore(), authz.NewTokenMinter("unit-test-secret-key-1234567890", 15*time.Minute), nil, nil)
}

func originCall(s *Server, host string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	req.Host = host
	req.RemoteAddr = "127.0.0.1:1234"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestSameOriginBrowserPostIsAcceptedOnLocalhost(t *testing.T) {
	s := originServer()
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "[::1]:8080"} {
		if w := originCall(s, host, map[string]string{"Origin": "http://" + host}); w.Code == http.StatusForbidden {
			t.Errorf("same-origin request from %s must not be blocked", host)
		}
	}
}

// The device-login portal posts a form; with strict referrer policies browsers send
// "Origin: null" for it. The browser-controlled Sec-Fetch-Site proves it was same-origin.
func TestNullOriginSameOriginFormPostIsAccepted(t *testing.T) {
	s := originServer()
	if w := originCall(s, "localhost:8080", map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}); w.Code == http.StatusForbidden {
		t.Fatal("a same-origin form POST that carries Origin: null must be accepted")
	}
}

func TestOtherNullOriginsAndForeignOriginsAreStillRejected(t *testing.T) {
	s := originServer()
	cases := map[string]map[string]string{
		"null origin, cross-site":           {"Origin": "null", "Sec-Fetch-Site": "cross-site"},
		"null origin, no fetch metadata":    {"Origin": "null"},
		"null origin, same-site only":       {"Origin": "null", "Sec-Fetch-Site": "same-site"},
		"foreign origin":                    {"Origin": "https://evil.example"},
		"foreign origin claiming same-site": {"Origin": "https://evil.example", "Sec-Fetch-Site": "same-origin"},
	}
	for name, h := range cases {
		if w := originCall(s, "localhost:8080", h); w.Code != http.StatusForbidden {
			t.Errorf("%s must be rejected, got %d", name, w.Code)
		}
	}
}

func TestReferrerPolicyDoesNotForceNullOrigin(t *testing.T) {
	w := originCall(originServer(), "localhost:8080", nil)
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy must be same-origin so same-origin form posts carry a real Origin, got %q", got)
	}
}
