package api

import (
	"bap-controlplane/pkg/types"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestDiscoveryDeliveryEndToEnd(t *testing.T) {
	if os.Getenv("BAP_TELEMETRY_E2E") != "1" {
		t.Skip("set BAP_TELEMETRY_E2E=1 for real edge collector delivery")
	}
	initial := setupTestServer()
	proof, _, err := initial.minter.MintWorkstationSession(&types.RegisteredAgent{AgentID: "station", AppID: "bapedge", InstanceID: "discovery-machine", UserEmail: "operator@example.test"}, "binary")
	if err != nil {
		t.Fatal(err)
	}
	var active atomic.Pointer[Server]
	active.Store(initial)
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/e2e/restart" {
			if r.Header.Get("Authorization") != "Bearer "+proof {
				w.WriteHeader(401)
				return
			}
			active.Store(setupTestServer())
			w.WriteHeader(200)
			return
		}
		if r.URL.Path == "/api/v1/discovery/shadow-it/scan" && attempts.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		active.Load().Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	command := exec.Command("go", "test", "./cmd", "-run", "^TestDiscoveryAgainstControlPlane$", "-count=1", "-timeout=45s")
	command.Dir = filepath.Join(root, "bap-edge")
	command.Env = append(os.Environ(), "BAP_DISCOVERY_E2E_URL="+server.URL, "BAP_DISCOVERY_E2E_PROOF="+proof)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("edge collector failed: %v\n%s", err, output)
	}
	t.Logf("real edge collector: %s", output)
	page, err := active.Load().inventory.List("discovery-machine", "", "present", "", 50, 0)
	if err != nil || page.Total != 2 {
		t.Fatalf("restart replay inventory: %+v %v", page, err)
	}
	for _, asset := range page.Findings {
		if asset.Owner != "operator@example.test" || asset.Evidence != "configured" || asset.Mediation != "not_observed" {
			t.Fatalf("forged authority: %+v", asset)
		}
	}
	if len(active.Load().sessionStore.List(10)) != 0 {
		t.Fatal("discovery invented agent execution sessions")
	}
}
