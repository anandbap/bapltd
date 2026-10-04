package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/otc"
	"bap-controlplane/internal/policy"
	"bap-controlplane/internal/registry"
	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

func setupTestServerForOIDC() (*Server, *httptest.Server) {
	regStore := registry.NewStore("bap.internal")
	otcStore := otc.NewStore()
	minter := authz.NewTokenMinter("test-secret-key-32-bytes-minimum!", 15*time.Minute)
	policyStore := policy.NewStore("", "")
	auditStore := audit.NewStore()
	sessionStore := session.NewStore()

	s := NewServer(regStore, otcStore, minter, policyStore, auditStore, sessionStore)
	s.SetAdminSecurity("test-admin-secret-token", true)
	ts := httptest.NewServer(s.mux)
	return s, ts
}

func TestDevOTCRequest_DevMode(t *testing.T) {
	_, ts := setupTestServerForOIDC()
	defer ts.Close()

	// 1. Request dev OTC in default dev mode
	body, _ := json.Marshal(types.DevOTCRequest{
		AppID:      "test-dev-agent",
		OwnerEmail: "dev@corp.internal",
		AgentName:  "Dev Laptop",
	})
	resp, err := http.Post(ts.URL+"/api/v1/auth/otc/dev-request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Dev OTC request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected HTTP 201 Created, got %d", resp.StatusCode)
	}

	var devResp types.DevOTCResponse
	if err := json.NewDecoder(resp.Body).Decode(&devResp); err != nil {
		t.Fatalf("failed to decode dev OTC response: %v", err)
	}

	if devResp.Code == "" || devResp.AgentID == "" {
		t.Fatalf("invalid Dev OTC response: %+v", devResp)
	}
	if devResp.Mode != "development" {
		t.Errorf("expected mode=development, got %s", devResp.Mode)
	}

	// 2. Test enrolling with this dev OTC
	regBody, _ := json.Marshal(types.RegisterEdgeRequest{
		Code:       devResp.Code,
		BinaryHash: "baphsh_mock_dev_binary_12345",
		Hostname:   "dev-workstation",
		OS:         "windows",
		Arch:       "amd64",
	})
	regResp, err := http.Post(ts.URL+"/api/v1/agents/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatalf("agent register with dev OTC failed: %v", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK on enrollment with dev OTC, got %d", regResp.StatusCode)
	}
}

func TestDevOTCRequest_ProdMode(t *testing.T) {
	s, ts := setupTestServerForOIDC()
	defer ts.Close()

	// Set server to production mode
	s.SetEnvironmentMode("prod")
	if !s.IsProductionMode() {
		t.Fatal("expected server to be in production mode")
	}

	// 1. Dev OTC request must fail with 403 Forbidden
	body, _ := json.Marshal(types.DevOTCRequest{
		AppID:      "test-prod-attempt",
		OwnerEmail: "attacker@external.com",
	})
	resp, err := http.Post(ts.URL+"/api/v1/auth/otc/dev-request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Dev OTC request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden in prod mode, got %d", resp.StatusCode)
	}

	// 2. Offline administrative pre-registration with X-BAP-Admin-Token must still succeed
	preReqBody, _ := json.Marshal(types.PreRegisterRequest{
		AppID:           "prod-server-agent",
		OwnerEmail:      "secops@corp.internal",
		AgentName:       "Production Pipeline Agent",
		EnvProfile:      types.ProfileProd,
		PermittedScopes: []string{"cli:exec"},
	})
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agents/pre-register", bytes.NewReader(preReqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-BAP-Admin-Token", "test-admin-secret-token")

	client := &http.Client{}
	adminResp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("Admin pre-register request failed: %v", err)
	}
	defer adminResp.Body.Close()

	if adminResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected HTTP 201 for offline admin pre-registration, got %d", adminResp.StatusCode)
	}
}

func TestOIDCDeviceFlow_EndToEnd(t *testing.T) {
	_, ts := setupTestServerForOIDC()
	defer ts.Close()

	// 1. Initiate Device Code Flow
	deviceReq, _ := json.Marshal(types.OIDCDeviceCodeRequest{
		ClientID:   "bap-edge-cli",
		Scope:      "openid profile email groups",
		Provider:   "entra",
		Hostname:   "alice-thinkpad",
		BinaryHash: "baphsh_alice_bapedge_v1",
		AppID:      "claude-code-workstation",
	})
	respCode, err := http.Post(ts.URL+"/api/v1/auth/oidc/device-code", "application/json", bytes.NewReader(deviceReq))
	if err != nil {
		t.Fatalf("device code request failed: %v", err)
	}
	defer respCode.Body.Close()

	if respCode.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", respCode.StatusCode)
	}

	var codeResp types.OIDCDeviceCodeResponse
	if err := json.NewDecoder(respCode.Body).Decode(&codeResp); err != nil {
		t.Fatalf("decode device code resp failed: %v", err)
	}

	if codeResp.DeviceCode == "" || codeResp.UserCode == "" {
		t.Fatalf("invalid code response: %+v", codeResp)
	}

	// 2. Poll token before approval -> must return authorization_pending (RFC 8628)
	tokenReq, _ := json.Marshal(types.OIDCDeviceTokenRequest{DeviceCode: codeResp.DeviceCode})
	respPending, err := http.Post(ts.URL+"/api/v1/auth/oidc/device-token", "application/json", bytes.NewReader(tokenReq))
	if err != nil {
		t.Fatalf("poll token failed: %v", err)
	}
	defer respPending.Body.Close()

	if respPending.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for pending token, got %d", respPending.StatusCode)
	}

	var pendingResp map[string]string
	_ = json.NewDecoder(respPending.Body).Decode(&pendingResp)
	if pendingResp["error"] != "authorization_pending" {
		t.Fatalf("expected error=authorization_pending, got %s", pendingResp["error"])
	}

	// 3. User approves in browser/MFA portal -> verify endpoint
	verifyReq, _ := json.Marshal(types.OIDCDeviceVerifyRequest{
		UserCode:   codeResp.UserCode,
		UserEmail:  "alice@corp.internal",
		Department: "Finance",
		Groups:     []string{"finance-team", "cloud-engineers"},
		Provider:   "entra",
	})
	respVerify, err := http.Post(ts.URL+"/api/v1/auth/oidc/device-verify", "application/json", bytes.NewReader(verifyReq))
	if err != nil {
		t.Fatalf("device verify failed: %v", err)
	}
	defer respVerify.Body.Close()

	if respVerify.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 on verify, got %d", respVerify.StatusCode)
	}

	// 4. Poll token after approval -> must return authorized with corporate claims
	respAuthorized, err := http.Post(ts.URL+"/api/v1/auth/oidc/device-token", "application/json", bytes.NewReader(tokenReq))
	if err != nil {
		t.Fatalf("poll authorized token failed: %v", err)
	}
	defer respAuthorized.Body.Close()

	if respAuthorized.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 for authorized token, got %d", respAuthorized.StatusCode)
	}

	var authResp types.OIDCDeviceTokenResponse
	if err := json.NewDecoder(respAuthorized.Body).Decode(&authResp); err != nil {
		t.Fatalf("decode authorized token resp failed: %v", err)
	}

	if authResp.Status != "authorized" {
		t.Errorf("expected status=authorized, got %s", authResp.Status)
	}
	if authResp.UserEmail != "alice@corp.internal" {
		t.Errorf("expected email=alice@corp.internal, got %s", authResp.UserEmail)
	}
	if authResp.Department != "Finance" {
		t.Errorf("expected department=Finance, got %s", authResp.Department)
	}
	if len(authResp.Groups) != 2 || authResp.Groups[0] != "finance-team" {
		t.Errorf("expected groups=[finance-team, cloud-engineers], got %v", authResp.Groups)
	}
	if authResp.SessionToken == "" {
		t.Error("expected non-empty SessionToken")
	}
}
