package dashboardui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDashboardServesAssetsAndProxiesAPI(t *testing.T) {
	var expectedHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != expectedHost {
			t.Errorf("proxy did not rewrite host: %q", r.Host)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"upstream"}`))
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	expectedHost = target.Host
	handler := Handler(target, http.DefaultTransport, false)

	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest("GET", "/dashboard/", nil))
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Agent operations") {
		t.Fatalf("dashboard asset response: %d", page.Code)
	}

	api := httptest.NewRecorder()
	handler.ServeHTTP(api, httptest.NewRequest("GET", "/api/v1/health", nil))
	if api.Code != 200 || !strings.Contains(api.Body.String(), "upstream") {
		t.Fatalf("proxied API response: %d %s", api.Code, api.Body.String())
	}

	config := httptest.NewRecorder()
	handler.ServeHTTP(config, httptest.NewRequest("GET", "/dashboard-config", nil))
	if config.Code != 200 || !strings.Contains(config.Body.String(), upstream.URL) {
		t.Fatalf("dashboard config response: %d %s", config.Code, config.Body.String())
	}

	inspector := httptest.NewRecorder()
	handler.ServeHTTP(inspector, httptest.NewRequest("GET", "/inspector", nil))
	if inspector.Code != 302 || !strings.Contains(inspector.Header().Get("Location"), "/dashboard/") {
		t.Fatalf("expected redirect to /dashboard/, got: %d %s", inspector.Code, inspector.Body.String())
	}

	inspectorV2 := httptest.NewRecorder()
	handler.ServeHTTP(inspectorV2, httptest.NewRequest("GET", "/inspector_v2", nil))
	if inspectorV2.Code != 302 || !strings.Contains(inspectorV2.Header().Get("Location"), "/dashboard/") {
		t.Fatalf("expected redirect to /dashboard/, got: %d %s", inspectorV2.Code, inspectorV2.Body.String())
	}

	// Agent Watch V2 workspace route test
	v2Page := httptest.NewRecorder()
	handler.ServeHTTP(v2Page, httptest.NewRequest("GET", "/dashboard/v2/", nil))
	if v2Page.Code != 200 || !strings.Contains(v2Page.Body.String(), "Agent Watch V2") {
		t.Fatalf("v2 dashboard asset response: %d", v2Page.Code)
	}

	// Dedicated V1 routes test
	v1Redirect := httptest.NewRecorder()
	handler.ServeHTTP(v1Redirect, httptest.NewRequest("GET", "/dashboard/v1", nil))
	if v1Redirect.Code != 307 || v1Redirect.Header().Get("Location") != "/dashboard/v1/" {
		t.Fatalf("v1 redirect response: %d, location: %s", v1Redirect.Code, v1Redirect.Header().Get("Location"))
	}

	v1Page := httptest.NewRecorder()
	handler.ServeHTTP(v1Page, httptest.NewRequest("GET", "/dashboard/v1/", nil))
	if v1Page.Code != 200 || !strings.Contains(v1Page.Body.String(), "BAP Control Plane") {
		t.Fatalf("v1 dashboard asset response: %d", v1Page.Code)
	}

	// Legacy V1 preservation route test
	legacyPage := httptest.NewRecorder()
	handler.ServeHTTP(legacyPage, httptest.NewRequest("GET", "/dashboard/?v=legacy", nil))
	if legacyPage.Code != 200 || !strings.Contains(legacyPage.Body.String(), "BAP Control Plane") {
		t.Fatalf("legacy dashboard asset response: %d", legacyPage.Code)
	}
}

func TestRemoteAdministrativeProxyIsDeniedByDefault(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:1")
	handler := Handler(target, http.DefaultTransport, false)
	r := httptest.NewRequest("POST", "/api/v1/control/kill-switch", strings.NewReader(`{"enabled":true}`))
	r.RemoteAddr = "203.0.113.9:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("remote admin request status %d, want 403", w.Code)
	}
}
