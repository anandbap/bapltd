package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func setupTestServerForSTS(t *testing.T) (*Server, *session.Store) {
	t.Helper()

	regStore := registry.NewStore("bap.internal")
	otcStore := otc.NewStore()
	minter := authz.NewTokenMinter("sts-test-signing-key-32bytesmin!", 15*time.Minute)
	policyStore := policy.NewStore("permit(principal, action, resource);", "")
	auditStore := audit.NewStore()
	sessionStore := session.NewStore()

	srv := NewServer(regStore, otcStore, minter, policyStore, auditStore, sessionStore)
	return srv, sessionStore
}

func TestSTSTokenExchange_AuthorizedGitFlow(t *testing.T) {
	srv, sStore := setupTestServerForSTS(t)

	// 1. Create active attested session
	sessID := "sess-git-authorized-01"
	_, err := sStore.Start(session.SessionStartRequest{
		SessionID:  sessID,
		AppID:      "claude-code",
		InstanceID: "dev-workstation-01",
		UserEmail:  "developer@company.corp",
	})
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// 2. Request RFC 8693 token exchange for GitHub push authority
	reqBody := types.RFC8693TokenExchangeRequest{
		GrantType:          types.RFC8693GrantTypeTokenExchange,
		SubjectToken:       "spiffe://bap.internal/workstation/dev-workstation-01/session/" + sessID,
		SubjectTokenType:   types.RFC8693TokenTypeSVID,
		Audience:           "github",
		Scope:              "repo:push",
		Resource:           "repo:bapltd",
		RequestedTokenType: types.RFC8693TokenTypeAccessToken,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sts/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleSTSToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.RFC8693TokenExchangeResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode STS response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Fatal("Expected non-empty access_token")
	}
	if !strings.HasPrefix(resp.AccessToken, "saas-github-") {
		t.Errorf("Expected token prefix saas-github-, got %s", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Expected token_type Bearer, got %s", resp.TokenType)
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("Expected 300s TTL, got %d", resp.ExpiresIn)
	}
	if resp.Scope != "repo:push" {
		t.Errorf("Expected scope repo:push, got %s", resp.Scope)
	}

	// 3. Verify downstream SaaS token usage strictly inside bound session
	allowed, status, err := srv.saasTokenMgr.VerifyUsage(resp.AccessToken, sessID, "repo:push")
	if !allowed || err != nil {
		t.Fatalf("Expected token verification to succeed in bound session: status=%s, err=%v", status, err)
	}
}

func TestSTSTokenExchange_PrivilegeEscalationBlocked(t *testing.T) {
	srv, sStore := setupTestServerForSTS(t)

	sessID := "sess-escalation-test"
	_, _ = sStore.Start(session.SessionStartRequest{
		SessionID:  sessID,
		AppID:      "codex-cli",
		UserEmail:  "developer@company.corp",
	})

	// Attempt to request forbidden scopes: admin:org and delete_repo
	for _, forbiddenScope := range []string{"admin:org", "delete_repo", "admin:enterprise"} {
		reqBody := types.RFC8693TokenExchangeRequest{
			GrantType:        types.RFC8693GrantTypeTokenExchange,
			SubjectToken:     sessID,
			SubjectTokenType: types.RFC8693TokenTypeAccessToken,
			Audience:         "github",
			Scope:            forbiddenScope,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sts/token", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		srv.handleSTSToken(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403 Forbidden for escalation scope %s, got %d: %s",
				forbiddenScope, w.Code, w.Body.String())
		}

		if !strings.Contains(w.Body.String(), "invalid_scope") {
			t.Errorf("Expected invalid_scope error, got: %s", w.Body.String())
		}
	}
}

func TestSTSTokenExchange_SessionBindingViolation(t *testing.T) {
	srv, sStore := setupTestServerForSTS(t)

	sessionA := "sess-legitimate-agent-a"
	sessionB := "sess-rogue-attacker-b"

	_, _ = sStore.Start(session.SessionStartRequest{SessionID: sessionA, AppID: "claude-code"})
	_, _ = sStore.Start(session.SessionStartRequest{SessionID: sessionB, AppID: "untrusted-agent"})

	// Mint token for Session A
	reqBody := types.RFC8693TokenExchangeRequest{
		GrantType:    types.RFC8693GrantTypeTokenExchange,
		SubjectToken: sessionA,
		Audience:     "github",
		Scope:        "repo:push",
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sts/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleSTSToken(w, req)

	var resp types.RFC8693TokenExchangeResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)

	// Session B attempts to use Session A's downstream token
	allowed, status, err := srv.saasTokenMgr.VerifyUsage(resp.AccessToken, sessionB, "repo:push")
	if allowed || err == nil {
		t.Fatal("Expected cross-session hijack attempt to be blocked!")
	}
	if !errors.Is(err, authz.ErrSessionBindingViolation) {
		t.Errorf("Expected ErrSessionBindingViolation, got: %v", err)
	}
	if status != "SessionBindingViolation" {
		t.Errorf("Expected status SessionBindingViolation, got: %s", status)
	}
}

func TestSTSTokenExchange_SingleUseReplayProtection(t *testing.T) {
	srv, sStore := setupTestServerForSTS(t)

	sessID := "sess-single-use-01"
	_, _ = sStore.Start(session.SessionStartRequest{SessionID: sessID, AppID: "antigravity"})

	// Request token with max_uses = 1
	reqBody := types.RFC8693TokenExchangeRequest{
		GrantType:    types.RFC8693GrantTypeTokenExchange,
		SubjectToken: sessID,
		Audience:     "github",
		Scope:        "repo:push",
		MaxUses:      1,
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sts/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleSTSToken(w, req)

	var resp types.RFC8693TokenExchangeResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)

	// 1st use: Allowed
	allowed, _, err := srv.saasTokenMgr.VerifyUsage(resp.AccessToken, sessID, "repo:push")
	if !allowed || err != nil {
		t.Fatalf("First single-use should succeed, got err: %v", err)
	}

	// 2nd use (Replay): Strictly Rejected
	allowed2, status2, err2 := srv.saasTokenMgr.VerifyUsage(resp.AccessToken, sessID, "repo:push")
	if allowed2 || err2 == nil {
		t.Fatal("Expected replay attack on burned single-use token to be blocked!")
	}
	if !errors.Is(err2, authz.ErrGrantAlreadyBurned) {
		t.Errorf("Expected ErrGrantAlreadyBurned, got: %v", err2)
	}
	if status2 != "GrantAlreadyBurned" {
		t.Errorf("Expected status GrantAlreadyBurned, got: %s", status2)
	}
}

func TestSTSTokenExchange_RevokedSessionDenied(t *testing.T) {
	srv, sStore := setupTestServerForSTS(t)

	sessID := "sess-compromised"
	_, _ = sStore.Start(session.SessionStartRequest{SessionID: sessID, AppID: "claude-code"})
	_ = sStore.RevokeSession(sessID, "Admin containment")

	reqBody := types.RFC8693TokenExchangeRequest{
		GrantType:    types.RFC8693GrantTypeTokenExchange,
		SubjectToken: sessID,
		Audience:     "github",
		Scope:        "repo:push",
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sts/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleSTSToken(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for revoked session, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access_denied") {
		t.Errorf("Expected access_denied OAuth error, got: %s", w.Body.String())
	}
}

func TestSTSTokenExchange_FormUrlEncoded(t *testing.T) {
	srv, sStore := setupTestServerForSTS(t)

	sessID := "sess-curl-client"
	_, _ = sStore.Start(session.SessionStartRequest{SessionID: sessID, AppID: "copilot"})

	formData := url.Values{
		"grant_type":    {types.RFC8693GrantTypeTokenExchange},
		"subject_token": {sessID},
		"audience":      {"github"},
		"scope":         {"repo:push"},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sts/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleSTSToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for form-urlencoded request, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.RFC8693TokenExchangeResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.AccessToken == "" || resp.Scope != "repo:push" {
		t.Errorf("Unexpected token response: %+v", resp)
	}
}

func TestSTSInspector_ListExchanges(t *testing.T) {
	srv, sStore := setupTestServerForSTS(t)

	sessID := "sess-inspector-test"
	_, _ = sStore.Start(session.SessionStartRequest{SessionID: sessID, AppID: "opencode"})

	// Trigger exchange
	reqBody := types.RFC8693TokenExchangeRequest{
		GrantType:    types.RFC8693GrantTypeTokenExchange,
		SubjectToken: sessID,
		Audience:     "github",
		Scope:        "repo:push",
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sts/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleSTSToken(w, req)

	// Inspect
	reqInsp := httptest.NewRequest(http.MethodGet, "/api/v1/sts/inspector", nil)
	wInsp := httptest.NewRecorder()
	srv.handleSTSInspector(wInsp, reqInsp)

	if wInsp.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for inspector, got %d", wInsp.Code)
	}

	var inspResult map[string]interface{}
	if err := json.NewDecoder(wInsp.Body).Decode(&inspResult); err != nil {
		t.Fatalf("Failed to parse inspector JSON: %v", err)
	}

	exchanges, ok := inspResult["exchanges"].([]interface{})
	if !ok || len(exchanges) == 0 {
		t.Fatalf("Expected at least one recorded exchange in inspector: %+v", inspResult)
	}
}
