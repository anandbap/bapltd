package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"bap-controlplane/internal/session"
)

// Opt in with BAP_TELEMETRY_E2E=1. The child uses the actual edge audit sender
// and revocation authorizer over HTTP, not a reimplementation of either protocol.
func TestTelemetryDeliveryEndToEnd(t *testing.T) {
	if os.Getenv("BAP_TELEMETRY_E2E") != "1" {
		t.Skip("set BAP_TELEMETRY_E2E=1 for cross-module delivery test")
	}
	s := setupTestServer()
	s.SetAdminSecurity("e2e-admin", true)
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "telemetry-e2e", AppID: "claude-code", InstanceID: "e2e-machine"})
	if err != nil {
		t.Fatal(err)
	}
	proof:=recoveryProof(t,s,"e2e-machine")
	var active atomic.Pointer[Server];active.Store(s)
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path=="/e2e/restart" {
			if r.Header.Get("Authorization")!="Bearer "+proof{w.WriteHeader(401);return}
			fresh:=setupTestServer();fresh.SetAdminSecurity("e2e-admin",true);active.Store(fresh);w.WriteHeader(200);return
		}
		if r.URL.Path == "/api/v1/audit/ingest" && attempts.Add(1) == 1 {
			http.Error(w, "temporary ingest failure", http.StatusServiceUnavailable)
			return
		}
		active.Load().Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	cmd := exec.Command("go", "test", "./internal/audit", "-run", "^TestAuditDeliveryEndToEnd$", "-count=1", "-timeout=45s")
	cmd.Dir = filepath.Join(root, "bap-edge")
	cmd.Env = append(os.Environ(), "BAP_TELEMETRY_E2E_URL="+server.URL, "BAP_TELEMETRY_E2E_PROOF="+proof)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("edge-to-control-plane test failed: %v\n%s", err, output)
	}
	t.Logf("real edge sender: %s", output)
	s=active.Load()
	sess, err := s.sessionStore.Get("telemetry-e2e")
	if err != nil || sess.TotalEvents != 1 || sess.DeniedCount != 1 || sess.Status != "active" {
		t.Fatalf("incorrect final session: %+v %v", sess, err)
	}
	if valid, err := s.auditStore.VerifyChain(); !valid || err != nil {
		t.Fatalf("end-to-end chain invalid: %v", err)
	}
}
