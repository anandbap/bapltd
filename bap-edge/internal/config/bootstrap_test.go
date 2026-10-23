package config

import (
	"bap-edge/internal/httptransport"
	"bap-edge/internal/policystore"
	"bap-edge/internal/state"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestBootstrap_ExplicitEndpoint(t *testing.T) {
	state.ResetForTesting()
	defer state.ResetForTesting()

	os.Setenv("BAP_TEST_MODE", "1")
	defer os.Unsetenv("BAP_TEST_MODE")

	tempDir := t.TempDir()
	os.Setenv("BAP_STATE_DIR", tempDir)
	defer os.Unsetenv("BAP_STATE_DIR")

	cedarPath := filepath.Join(tempDir, "policy.cedar")
	_ = os.WriteFile(cedarPath, []byte("permit(principal, action, resource);"), 0600)

	mockURL := "https://mock.controlplane.internal"
	httptransport.MockTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		if r.URL.Path == "/health" {
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.Write([]byte(`{"status":"ok","version":"1.0.0"}`))
			return rec.Result(), nil
		}
		if r.URL.Path == "/api/v1/policy/sync" {
			rec.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rec).Encode(policystore.SyncResponse{
				Directive: "UPDATE_REQUIRED",
				Bundle: &policystore.Bundle{
					Version:     1,
					Digest:      policystore.ComputeDigest("permit(principal, action, resource);", ""),
					PolicyCedar: "permit(principal, action, resource);",
				},
			})
			return rec.Result(), nil
		}
		rec.WriteHeader(http.StatusNotFound)
		return rec.Result(), nil
	})
	defer func() { httptransport.MockTransport = nil }()

	res, err := BootstrapControlPlane(mockURL)
	t.Logf("DEBUG res: %+v, err: %v", res, err)
	if err != nil {
		t.Fatalf("expected successful bootstrap against explicit test server, got: %v", err)
	}
	if !res.Connected {
		t.Errorf("expected Connected = true, got false")
	}
	if res.DegradedMode {
		t.Errorf("expected DegradedMode = false when connected to mock server")
	}
	if res.ActiveURL != mockURL {
		t.Errorf("expected ActiveURL = %s, got %s", mockURL, res.ActiveURL)
	}
}

func TestBootstrap_DegradedModeWithLocalPolicy(t *testing.T) {
	state.ResetForTesting()
	defer state.ResetForTesting()

	os.Setenv("BAP_TEST_MODE", "1")
	defer os.Unsetenv("BAP_TEST_MODE")

	tempDir := t.TempDir()
	os.Setenv("BAP_STATE_DIR", tempDir)
	defer os.Unsetenv("BAP_STATE_DIR")

	polDir := filepath.Join(tempDir, "policy")
	_ = os.MkdirAll(polDir, 0700)
	_ = os.WriteFile(filepath.Join(polDir, "policy.cedar"), []byte("permit(principal, action, resource);"), 0600)
	polState := policystore.PolicyState{
		Version: 1,
		Digest:  policystore.ComputeDigest("permit(principal, action, resource);", ""),
	}
	stData, _ := json.Marshal(polState)
	_ = os.WriteFile(filepath.Join(polDir, "policy-state.json"), stData, 0600)

	// Point to unreachable server to force fallback
	unreachableServer := "http://127.0.0.1:59999"

	res, err := BootstrapControlPlane(unreachableServer)
	if err != nil {
		t.Fatalf("expected degraded mode with local policy, got error: %v", err)
	}
	if res.Connected {
		t.Errorf("expected Connected = false for unreachable server")
	}
	if !res.DegradedMode {
		t.Errorf("expected DegradedMode = true when control plane is down and local policy exists")
	}
	if res.PolicyPath == "" {
		t.Errorf("expected non-empty PolicyPath in degraded mode")
	}
}

func TestBootstrap_FailClosedWhenNoPolicyAndNoControlPlane(t *testing.T) {
	state.ResetForTesting()
	defer state.ResetForTesting()

	os.Setenv("BAP_TEST_MODE", "1")
	defer os.Unsetenv("BAP_TEST_MODE")

	emptyDir := t.TempDir()
	os.Setenv("BAP_STATE_DIR", emptyDir)
	defer os.Unsetenv("BAP_STATE_DIR")
	os.Setenv("BAP_WORKSPACE_ROOT", emptyDir)
	defer os.Unsetenv("BAP_WORKSPACE_ROOT")

	origWd, _ := os.Getwd()
	_ = os.Chdir(emptyDir)
	defer func() { _ = os.Chdir(origWd) }()

	deadServer := "http://127.0.0.1:59998"
	res, err := BootstrapControlPlane(deadServer)
	if err == nil {
		t.Fatalf("expected ErrNoPolicyAvailable when no control plane and no local policy, got: %+v", res)
	}
	if err != ErrNoPolicyAvailable {
		t.Errorf("expected ErrNoPolicyAvailable, got: %v", err)
	}
}
