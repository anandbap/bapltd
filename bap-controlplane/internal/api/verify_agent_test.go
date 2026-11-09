package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func setupTestServerRecorder() (*Server, *registry.Store, *otc.Store, *authz.TokenMinter) {
	regStore := registry.NewStore("bap.internal")
	otcStore := otc.NewStore()
	minter := authz.NewTokenMinter("test-secret-key-32-bytes-minimum!", 15*time.Minute)
	policyStore := policy.NewStore("", "")
	auditStore := audit.NewStore()
	sessionStore := session.NewStore()

	s := NewServer(regStore, otcStore, minter, policyStore, auditStore, sessionStore)
	s.SetAdminSecurity("test-admin-secret-token", true)
	return s, regStore, otcStore, minter
}

func TestVerifyAgent_MissingAgentID(t *testing.T) {
	s, _, _, _ := setupTestServerRecorder()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/verify", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["valid"] != false || resp["status"] != "missing_parameter" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestVerifyAgent_NotFound(t *testing.T) {
	s, _, _, _ := setupTestServerRecorder()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/verify?agent_id=non-existent-agent-id", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["valid"] != false || resp["status"] != "not_found" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestVerifyAgent_ActiveAgent(t *testing.T) {
	s, regStore, _, minter := setupTestServerRecorder()

	enrolled, err := regStore.EnrollWorkstation(types.RegisteredAgent{
		AppID:       "workstation-desktop",
		AgentName:   "developer@internal.local @ DESKTOP-TEST (Desktop Workstation)",
		UserEmail:   "developer@internal.local",
		Hostname:    "DESKTOP-TEST",
		DeviceType:  "desktop",
		IdPProvider: "google",
	})
	if err != nil {
		t.Fatalf("failed to enroll workstation: %v", err)
	}

	token, _, err := minter.Mint(enrolled, "mock-hash", nil)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/verify?agent_id="+enrolled.AgentID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["valid"] != true || resp["status"] != "active" {
		t.Fatalf("expected valid=true status=active, got %+v", resp)
	}
	if resp["agent_name"] != "developer@internal.local @ DESKTOP-TEST (Desktop Workstation)" {
		t.Fatalf("unexpected agent_name: %v", resp["agent_name"])
	}
}

func TestVerifyAgent_Deregistered(t *testing.T) {
	s, regStore, _, minter := setupTestServerRecorder()

	enrolled, _ := regStore.EnrollWorkstation(types.RegisteredAgent{
		AppID:      "workstation-desktop",
		AgentName:  "dev@internal.local @ DESKTOP-OLD (Desktop Workstation)",
		UserEmail:  "dev@internal.local",
		Hostname:   "DESKTOP-OLD",
		DeviceType: "desktop",
	})
	_, _ = regStore.Deregister(enrolled.AgentID)

	token, _, _ := minter.Mint(enrolled, "mock-hash", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/verify?agent_id="+enrolled.AgentID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["valid"] != false || resp["status"] != "deregistered" {
		t.Fatalf("expected valid=false status=deregistered, got %+v", resp)
	}
}

func TestDevOTCRequest_WorkstationNaming(t *testing.T) {
	s, _, otcStore, _ := setupTestServerRecorder()

	body, _ := json.Marshal(types.DevOTCRequest{
		AppID:      "claude-code",
		OwnerEmail: "user@internal.local",
		Hostname:   "DESKTOP-E63V3UH",
		DeviceType: "desktop",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otc/dev-request", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}
	var devResp types.DevOTCResponse
	if err := json.NewDecoder(w.Body).Decode(&devResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify agent registered in registry has standardized name
	agentID, err := otcStore.Consume(devResp.Code)
	if err != nil {
		t.Fatalf("failed to consume OTC: %v", err)
	}

	agent, err := s.registry.Get(agentID)
	if err != nil {
		t.Fatalf("failed to get agent: %v", err)
	}

	expectedName := "user@internal.local @ DESKTOP-E63V3UH (Desktop Workstation)"
	if agent.AgentName != expectedName {
		t.Fatalf("expected agent name %q, got %q", expectedName, agent.AgentName)
	}
	if !strings.Contains(agent.AgentName, "@") {
		t.Fatalf("agent name does not contain @: %q", agent.AgentName)
	}
}
