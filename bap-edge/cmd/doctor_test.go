package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bap-edge/internal/pinning"
	"bap-edge/internal/policystore"
)

func TestDoctorOfflinePolicyReporting(t *testing.T) {
	// Point to a non-existent port to test offline resilience reporting
	t.Setenv("BAP_CONTROL_PLANE_URL", "http://127.0.0.1:59999")

	err := RunDoctor([]string{})
	if err != nil {
		t.Fatalf("expected doctor to succeed with offline warning/pass, got error: %v", err)
	}
}

func TestDoctorOnlinePolicySyncAndPinReconciliation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bap-doctor-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	policyContent := `permit(principal, action, resource);`
	policyFile := filepath.Join(tmpDir, "policy.cedar")
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	digest := policystore.ComputeDigest(policyContent, "")

	// Spin up mock control plane serving /api/v1/policy/sync
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/policy/sync" {
			resp := policystore.SyncResponse{
				Directive: "CURRENT",
				Bundle: &policystore.Bundle{
					Version:     1,
					Digest:      digest,
					PolicyCedar: policyContent,
					UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	t.Setenv("BAP_CONTROL_PLANE_URL", server.URL)
	t.Setenv("BAP_STATE_DIR", filepath.Join(tmpDir, ".bapstate"))

	// Create a pins.json with a drifted hash for policy.cedar
	pinsDir := filepath.Join(tmpDir, ".bapstate")
	_ = os.MkdirAll(pinsDir, 0700)
	manifestPath := filepath.Join(pinsDir, "pins.json")
	m := pinning.NewManifest()
	m.Assets["prompt:policy.cedar"] = pinning.PinnedAsset{
		ID:           "prompt:policy.cedar",
		AssetType:    "prompt",
		Path:         policyFile,
		ExpectedHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		AgentScope:   "all",
	}
	if err := pinning.SaveManifest(m, manifestPath); err != nil {
		t.Fatal(err)
	}

	// Verify that reconcilePolicyPin reconciles the drifted pin
	reconciled, newHash, err := reconcilePolicyPin(policyFile)
	if err != nil {
		t.Fatalf("reconcilePolicyPin failed: %v", err)
	}
	if !reconciled {
		t.Fatal("expected reconcilePolicyPin to return true for drifted pin")
	}

	// Reload manifest and verify hash was updated
	loaded, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Assets["prompt:policy.cedar"].ExpectedHash != newHash {
		t.Fatalf("expected updated hash %s, got %s", newHash, loaded.Assets["prompt:policy.cedar"].ExpectedHash)
	}

	// Run doctor and ensure it succeeds
	if err := RunDoctor([]string{}); err != nil {
		t.Fatalf("RunDoctor failed: %v", err)
	}
}
