package tokenexchange

import (
	"strings"
	"testing"
	"time"
)

func TestTokenExchangeGateway_SingleUseBurn(t *testing.T) {
	gw := NewTokenExchangeGateway("test-secret-key-1234")

	grantToken := "grant-abc-123-single-use"

	// 1. First burn succeeds
	burned, status, err := gw.BurnGrantOnce(grantToken)
	if !burned || err != nil {
		t.Fatalf("expected first burn to succeed, got burned=%v, status=%s, err=%v", burned, status, err)
	}

	// 2. Immediate replay must fail with GrantAlreadyBurned
	burned2, status2, err2 := gw.BurnGrantOnce(grantToken)
	if burned2 || err2 == nil {
		t.Fatalf("expected replay burn to fail, got burned=%v, status=%s, err=%v", burned2, status2, err2)
	}
	if !strings.Contains(status2, "GrantAlreadyBurned") {
		t.Errorf("expected status 'GrantAlreadyBurned', got %s", status2)
	}
}

func TestTokenExchangeGateway_BrokerDownstreamCredential(t *testing.T) {
	gw := NewTokenExchangeGateway("test-secret-key-1234")

	// Approved service: railway
	cred, err := gw.BrokerDownstreamCredential("railway", "staging", "task-deploy-001", "sess-123", "grant-valid-001")
	if err != nil {
		t.Fatalf("expected broker credential to succeed, got err=%v", err)
	}

	if cred.Service != "railway" {
		t.Errorf("expected service 'railway', got %s", cred.Service)
	}
	if cred.TargetEnv != "staging" {
		t.Errorf("expected target_env 'staging', got %s", cred.TargetEnv)
	}
	if !strings.HasPrefix(cred.EphemeralToken, "jit-railway-staging-") {
		t.Errorf("expected token prefix 'jit-railway-staging-', got %s", cred.EphemeralToken)
	}
	if cred.ExpiresAt.Sub(cred.IssuedAt) > 6*time.Minute || cred.ExpiresAt.Sub(cred.IssuedAt) < 4*time.Minute {
		t.Errorf("expected ~5min TTL, got %v", cred.ExpiresAt.Sub(cred.IssuedAt))
	}

	// Replay with the same grant token must fail
	_, errReplay := gw.BrokerDownstreamCredential("railway", "staging", "task-deploy-001", "sess-123", "grant-valid-001")
	if errReplay == nil {
		t.Fatal("expected replay attack with same grant token to be rejected")
	}

	// Unapproved service: attacker-service
	_, errUnapproved := gw.BrokerDownstreamCredential("unapproved-service", "dev", "task-002", "sess-123", "grant-fresh-002")
	if errUnapproved == nil {
		t.Fatal("expected unapproved service to be rejected")
	}
}

func TestTokenExchangeGateway_RFC8693Exchange(t *testing.T) {
	gw := NewTokenExchangeGateway("test-secret-rfc8693-key")

	req := RFC8693TokenExchangeRequest{
		GrantType:        RFC8693GrantTypeTokenExchange,
		Resource:         "https://api.github.com",
		Audience:         "https://api.github.com",
		Scope:            "repo:read issues:read",
		AuthorizedScopes: "repo:read issues:read repo:write",
		SubjectToken:     "bap-grant-single-use-7788",
		SubjectTokenType: RFC8693TokenTypeAccessToken,
		SessionID:        "sess-copilot-01",
		TaskID:           "task-code-review",
	}

	// 1. Successful RFC 8693 exchange
	resp, err := gw.ExchangeRFC8693Token(req)
	if err != nil {
		t.Fatalf("expected RFC 8693 exchange to succeed, got: %v", err)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn != 300 {
		t.Fatalf("unexpected token response format: %+v", resp)
	}
	if resp.Scope != "repo:read issues:read" {
		t.Fatalf("expected scope 'repo:read issues:read', got %s", resp.Scope)
	}

	// 2. Replay attack rejection (subject token burned)
	_, errReplay := gw.ExchangeRFC8693Token(req)
	if errReplay == nil {
		t.Fatalf("expected replay attack to be rejected with burned token")
	}

	// 3. Scope escalation rejection
	escalationReq := RFC8693TokenExchangeRequest{
		GrantType:        RFC8693GrantTypeTokenExchange,
		Resource:         "https://api.github.com",
		Scope:            "admin:org repo:delete", // Unauthorized scope
		AuthorizedScopes: "repo:read",
		SubjectToken:     "bap-grant-single-use-9999",
		SubjectTokenType: RFC8693TokenTypeAccessToken,
	}
	_, errEscalation := gw.ExchangeRFC8693Token(escalationReq)
	if errEscalation == nil {
		t.Fatalf("expected scope escalation attempt to be blocked")
	}

	// 4. Invalid grant type rejection
	invalidGrantReq := req
	invalidGrantReq.GrantType = "authorization_code"
	invalidGrantReq.SubjectToken = "bap-grant-fresh-1111"
	_, errGrantType := gw.ExchangeRFC8693Token(invalidGrantReq)
	if errGrantType == nil {
		t.Fatalf("expected invalid grant_type to be rejected")
	}
}
