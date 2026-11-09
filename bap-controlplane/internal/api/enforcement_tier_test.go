package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/otc"
	"bap-controlplane/internal/policy"
	"bap-controlplane/internal/registry"
)

func TestEnforcementTierAPI(t *testing.T) {
	reg := registry.NewStore("bap.internal")
	otcStore := otc.NewStore()
	minter := authz.NewTokenMinter("unit-test-secret-key-1234567890", 15*time.Minute)
	polStore := policy.NewStore("permit(principal, action, resource);", "{}")
	s := NewServer(reg, otcStore, minter, polStore, nil)
	s.SetAdminSecurity("admin-secret-test", false)

	// 1. Initial state must be Tier 1 Standard (StrictToolEnforcement = false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control/tier", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/control/tier, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Tier                  string `json:"tier"`
		StrictToolEnforcement bool   `json:"strict_tool_enforcement"`
		Description           string `json:"description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Tier != "tier_1_standard" {
		t.Errorf("expected default tier_1_standard, got %s", resp.Tier)
	}
	if resp.StrictToolEnforcement != false {
		t.Errorf("expected StrictToolEnforcement false by default, got %v", resp.StrictToolEnforcement)
	}

	// 2. POST without auth should be rejected
	postBody, _ := json.Marshal(map[string]interface{}{
		"strict_tool_enforcement": true,
	})
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/control/tier", bytes.NewReader(postBody))
	postReq.RemoteAddr = "127.0.0.1:1234"
	postW := httptest.NewRecorder()
	s.Handler().ServeHTTP(postW, postReq)
	if postW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized without admin token, got %d", postW.Code)
	}

	// 3. POST with admin auth should activate Tier 2 Strict
	postReqAuth := httptest.NewRequest(http.MethodPost, "/api/v1/control/tier", bytes.NewReader(postBody))
	postReqAuth.RemoteAddr = "127.0.0.1:1234"
	postReqAuth.Header.Set("Authorization", "Bearer admin-secret-test")
	postWAuth := httptest.NewRecorder()
	s.Handler().ServeHTTP(postWAuth, postReqAuth)

	if postWAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK activating tier 2, got %d: %s", postWAuth.Code, postWAuth.Body.String())
	}

	if err := json.Unmarshal(postWAuth.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode post response: %v", err)
	}
	if resp.Tier != "tier_2_strict" {
		t.Errorf("expected tier_2_strict after POST, got %s", resp.Tier)
	}
	if resp.StrictToolEnforcement != true {
		t.Errorf("expected StrictToolEnforcement true after POST, got %v", resp.StrictToolEnforcement)
	}

	// 4. Verify GET /api/v1/policy/tier reflects new state
	getReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/policy/tier", nil)
	getReq2.RemoteAddr = "127.0.0.1:1234"
	w2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(w2, getReq2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/policy/tier, got %d", w2.Code)
	}
	var resp2 struct {
		Tier                  string `json:"tier"`
		StrictToolEnforcement bool   `json:"strict_tool_enforcement"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp2.Tier != "tier_2_strict" || resp2.StrictToolEnforcement != true {
		t.Errorf("expected tier_2_strict and true, got %s, %v", resp2.Tier, resp2.StrictToolEnforcement)
	}

	// 5. Toggle back to Tier 1 Standard
	toggleBody, _ := json.Marshal(map[string]interface{}{
		"tier": "tier_1_standard",
	})
	toggleReq := httptest.NewRequest(http.MethodPost, "/api/v1/control/tier", bytes.NewReader(toggleBody))
	toggleReq.RemoteAddr = "127.0.0.1:1234"
	toggleReq.Header.Set("Authorization", "Bearer admin-secret-test")
	toggleW := httptest.NewRecorder()
	s.Handler().ServeHTTP(toggleW, toggleReq)

	if toggleW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK toggling back to tier 1, got %d", toggleW.Code)
	}
	if err := json.Unmarshal(toggleW.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Tier != "tier_1_standard" || resp.StrictToolEnforcement != false {
		t.Errorf("expected tier_1_standard and false, got %s, %v", resp.Tier, resp.StrictToolEnforcement)
	}
}
