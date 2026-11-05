package authz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthorizer_TamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.cedar")
	originalCedar := `permit (principal == Agent::"Local", action == Action::"Execute", resource == Command::"CLI");`
	if err := os.WriteFile(policyPath, []byte(originalCedar), 0600); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	digest := ComputePolicyDigest(originalCedar, "")
	statePath := filepath.Join(tmpDir, "policy-state.json")
	stateData, err := json.Marshal(map[string]interface{}{
		"version": 1,
		"digest":  digest,
	})
	if err != nil {
		t.Fatalf("failed to marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, stateData, 0600); err != nil {
		t.Fatalf("failed to write state: %v", err)
	}

	// 1. Untampered policy loads cleanly
	authz, err := NewAuthorizer(policyPath)
	if err != nil {
		t.Fatalf("expected clean authorizer load, got: %v", err)
	}
	if authz == nil {
		t.Fatalf("expected non-nil authorizer")
	}

	// 2. Tampered policy fails closed
	tamperedCedar := `permit (principal, action, resource); // tampered backdoor`
	if err := os.WriteFile(policyPath, []byte(tamperedCedar), 0600); err != nil {
		t.Fatalf("failed to overwrite policy: %v", err)
	}

	_, err = NewAuthorizer(policyPath)
	if err == nil {
		t.Fatalf("expected tamper detection error, got nil")
	}
	if !strings.Contains(err.Error(), "SECURITY ALERT: local policy.cedar integrity violation") {
		t.Fatalf("expected integrity violation alert, got: %v", err)
	}
}
