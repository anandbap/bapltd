package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunLogin_EndToEnd(t *testing.T) {
	// Set up mock control plane server
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/auth/oidc/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":          true,
			"provider":         "entra",
			"verification_uri": "https://login.microsoftonline.com/common/oauth2/deviceauth",
		})
	})

	mux.HandleFunc("/api/v1/auth/oidc/device-code", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "devcode-mock-12345",
			"user_code":                 "ABCD-WXYZ",
			"verification_uri":          "https://login.microsoftonline.com/common/oauth2/deviceauth",
			"verification_uri_complete": "http://localhost:8080/device?user_code=ABCD-WXYZ",
			"expires_in":                60,
			"interval":                  1,
		})
	})

	mux.HandleFunc("/api/v1/auth/oidc/device-verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "authorized",
		})
	})

	pollCount := 0
	mux.HandleFunc("/api/v1/auth/oidc/device-token", func(w http.ResponseWriter, r *http.Request) {
		pollCount++
		w.Header().Set("Content-Type", "application/json")
		// Authorize immediately
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "authorized",
			"user_email":    "alice@corp.internal",
			"department":    "Finance",
			"groups":        []string{"finance-team", "prod-deployers"},
			"agent_id":      "agent-mock-alice",
			"app_id":        "claude-code-workstation",
			"instance_id":   "inst-alice-01",
			"session_token": "mock-bap-session-jwt-token-123",
			"provider":      "entra",
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "credentials.json")

	args := []string{
		"--server", ts.URL,
		"--provider", "entra",
		"--email", "alice@corp.internal",
		"--department", "Finance",
		"--groups", "finance-team,prod-deployers",
		"--verify-now",
		"--config", configPath,
	}

	err := RunLogin(args)
	if err != nil {
		t.Fatalf("RunLogin failed: %v", err)
	}

	// Verify saved credentials
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("credentials file not found: %v", err)
	}

	var creds StoredCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		t.Fatalf("failed to parse credentials: %v", err)
	}

	if creds.AuthMode != "oidc" {
		t.Errorf("expected AuthMode=oidc, got %s", creds.AuthMode)
	}
	if creds.UserEmail != "alice@corp.internal" {
		t.Errorf("expected UserEmail=alice@corp.internal, got %s", creds.UserEmail)
	}
	if creds.Department != "Finance" {
		t.Errorf("expected Department=Finance, got %s", creds.Department)
	}
	if len(creds.Groups) != 2 || creds.Groups[0] != "finance-team" {
		t.Errorf("expected Groups=[finance-team, prod-deployers], got %v", creds.Groups)
	}
	if creds.SessionToken != "mock-bap-session-jwt-token-123" {
		t.Errorf("unexpected SessionToken: %s", creds.SessionToken)
	}
}
