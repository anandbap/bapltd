package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunLogout_LoggedOutAlready(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentCreds := filepath.Join(tmpDir, "does-not-exist.json")

	err := RunLogout([]string{"-config", nonExistentCreds})
	if err != nil {
		t.Fatalf("RunLogout should return nil when no credentials exist, got %v", err)
	}
}

func TestRunLogout_Success(t *testing.T) {
	deregisterCalled := false
	var receivedPayload map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agents/deregister" {
			deregisterCalled = true
			json.NewDecoder(r.Body).Decode(&receivedPayload)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"deregistered": true,
				"status":       "deregistered",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	credsPath := filepath.Join(tmpDir, "credentials.json")

	creds := StoredCredentials{
		ServerURL:    server.URL,
		AgentID:      "test-agent-logout",
		AppID:        "claude-code",
		InstanceID:   "inst-test-logout",
		SessionToken: "mock-jwt-token-xyz",
		UserEmail:    "test@corp.internal",
		IdPProvider:  "google",
		EnrolledAt:   time.Now(),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	if err := os.WriteFile(credsPath, data, 0600); err != nil {
		t.Fatalf("failed to write test credentials: %v", err)
	}

	// Execute RunLogout
	err := RunLogout([]string{"-config", credsPath, "-insecure"})
	if err != nil {
		t.Fatalf("RunLogout failed: %v", err)
	}

	if !deregisterCalled {
		t.Errorf("Expected /api/v1/agents/deregister to be called on control plane")
	}
	if receivedPayload["agent_id"] != "test-agent-logout" {
		t.Errorf("Expected agent_id 'test-agent-logout', got %q", receivedPayload["agent_id"])
	}

	// Verify local file is removed
	if _, err := os.Stat(credsPath); !os.IsNotExist(err) {
		t.Errorf("Expected %s to be deleted after logout, but file still exists", credsPath)
	}
}
