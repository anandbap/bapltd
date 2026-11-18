package api

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bap-controlplane/internal/tlsutil"
)

// Exercise the routed admin endpoint with security enabled. The original
// lifecycle fixture leaves admin security unconfigured.
func TestAdminDeploymentMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, remote, token string
		allowRemote         bool
		want                int
	}{
		{"local_missing", "127.0.0.1:1234", "", false, 401},
		{"local_invalid", "127.0.0.1:1234", "wrong", false, 403},
		{"local_valid", "127.0.0.1:1234", "test-admin", false, 200},
		{"ipv6_local_valid", "[::1]:1234", "test-admin", false, 200},
		{"remote_disabled", "192.0.2.1:1234", "test-admin", false, 403},
		{"remote_enabled_missing", "192.0.2.1:1234", "", true, 401},
		{"remote_enabled_invalid", "192.0.2.1:1234", "wrong", true, 403},
		{"remote_enabled_valid", "192.0.2.1:1234", "test-admin", true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := setupTestServer()
			s.SetAdminSecurity("test-admin", tc.allowRemote)
			r := httptest.NewRequest(http.MethodGet, "/api/v1/control/kill-switch", nil)
			r.RemoteAddr = tc.remote
			// Untrusted forwarding headers must not turn a remote caller local.
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestAdministrativeRoutesRejectMissingCredentials(t *testing.T) {
	for _, path := range []string{
		"/api/v1/control/kill-switch", "/api/v1/control/agent/kill",
		"/api/v1/control/agent/revoke", "/api/v1/sessions/revoke",
		"/api/v1/agents/revoke", "/api/v1/apps/revoke",
	} {
		t.Run(path, func(t *testing.T) {
			s := setupTestServer()
			s.SetAdminSecurity("test-admin", true)
			s.SetDemoMode(true)
			r := httptest.NewRequest(http.MethodPost, path, nil)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}

// The destructive demo endpoints were removed; they must not be served in any mode, even with demo
// mode on and a valid administrator credential.
func TestRemovedDemoRoutesAreNotServed(t *testing.T) {
	for _, path := range []string{
		"/api/v1/sessions/reset", "/api/v1/demo/exec-safe", "/api/v1/demo/exec-attack", "/api/v1/demo/fleet-scale",
	} {
		for _, demo := range []bool{false, true} {
			t.Run(path, func(t *testing.T) {
				s := setupTestServer()
				s.SetAdminSecurity("test-admin", true)
				s.SetDemoMode(demo)
				r := httptest.NewRequest(http.MethodPost, path, nil)
				r.Header.Set("Authorization", "Bearer test-admin")
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				// /sessions/reset now falls through to the generic /sessions/{id} route, which rejects
				// POST with 405; either way the reset action no longer exists.
				if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
					t.Fatalf("demo=%v: status = %d, want 404 or 405 (endpoint removed)", demo, w.Code)
				}
			})
		}
	}
}

// Real HTTPS transport, using BAP's certificate generator. Browser CORS and
// production CLI certificate selection still require separate integration tests.
func TestHTTPSDeploymentTrust(t *testing.T) {
	cert, pem, _, err := tlsutil.GenerateSelfSignedCert([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("invalid generated certificate")
	}
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	defer ts.Close()
	for _, tc := range []struct {
		name      string
		roots     *x509.CertPool
		host      string
		wantError bool
	}{
		{"trusted_ip", pool, "", false},
		{"trusted_dns", pool, "localhost", false},
		{"unknown_ca", x509.NewCertPool(), "", true},
		{"wrong_hostname", pool, "controlplane.example.test", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: tc.roots, ServerName: tc.host}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := client.Get(ts.URL + "/api/v1/health")
			if resp != nil {
				defer resp.Body.Close()
			}
			if tc.wantError {
				if err == nil {
					t.Fatal("expected certificate validation failure")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("health status = %d", resp.StatusCode)
			}
			// TLS trust must not substitute for administrative credentials.
			admin, err := client.Get(ts.URL + "/api/v1/control/kill-switch")
			if err != nil {
				t.Fatal(err)
			}
			defer admin.Body.Close()
			if admin.StatusCode != 401 {
				t.Fatalf("admin status = %d, want 401", admin.StatusCode)
			}
		})
	}
}
