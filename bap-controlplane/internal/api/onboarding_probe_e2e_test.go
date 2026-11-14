package api

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOnboardingProbeWireEndToEnd(t *testing.T) {
	if os.Getenv("BAP_TELEMETRY_E2E") != "1" {
		t.Skip("set BAP_TELEMETRY_E2E=1 for real edge/CP protocol validation")
	}
	// This fixture correlates captured prompt text and the git status command.
	// Opt in explicitly on both the server and inherited edge subprocess; the
	// default metadata policy intentionally removes those content fields.
	t.Setenv("BAP_TELEMETRY_CONTENT", "redacted")
	s := setupTestServer()
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	proof := recoveryProof(t, s, "probe-wire-machine")
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	command := exec.Command("go", "test", "./cmd", "-run", "^TestProbeWireAgainstControlPlane$", "-count=1", "-timeout=45s")
	command.Dir = filepath.Join(root, "bap-edge")
	command.Env = append(os.Environ(), "BAP_PROBE_E2E_URL="+server.URL, "BAP_PROBE_E2E_PROOF="+proof)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("probe protocol failed: %v\n%s", err, output)
	}
	t.Logf("edge CLI with synthetic native markers: %s", output)
}
