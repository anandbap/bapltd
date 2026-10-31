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

func TestSessionRecoveryEndToEnd(t *testing.T) {
	if os.Getenv("BAP_TELEMETRY_E2E") != "1" {
		t.Skip("set BAP_TELEMETRY_E2E=1")
	}
	initial := setupTestServer()
	_, _ = initial.sessionStore.Start(session.SessionStartRequest{SessionID: "restart-claude", AppID: "claude-code", InstanceID: "restart-machine"})
	proof := recoveryProof(t, initial, "restart-machine")
	var active atomic.Pointer[Server]
	active.Store(initial)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/e2e/restart" {
			if r.Header.Get("Authorization") != "Bearer "+proof {
				w.WriteHeader(401)
				return
			}
			fresh := setupTestServer()
			fresh.SetAdminSecurity("e2e-admin", true)
			active.Store(fresh)
			w.WriteHeader(200)
			return
		}
		active.Load().Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	cmd := exec.Command("go", "test", "./cmd", "-run", "^TestSessionRecoveryAgainstRestartedControlPlane$", "-v", "-count=1", "-timeout=45s")
	cmd.Dir = filepath.Join(root, "bap-edge")
	cmd.Env = append(os.Environ(), "BAP_RECOVERY_E2E_URL="+server.URL, "BAP_RECOVERY_E2E_PROOF="+proof)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restart E2E: %v\n%s", err, output)
	}
	t.Logf("real edge recovery: %s", output)
	sessions := active.Load().sessionStore.List(0)
	if len(sessions) != 1 || sessions[0].SessionID != "restart-claude" || sessions[0].Status != "revoked" {
		t.Fatalf("blocked recovery lost state: %+v", sessions)
	}
}
