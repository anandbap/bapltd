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
		t.Fatal("expected unapproved service to fail")
	}
}
