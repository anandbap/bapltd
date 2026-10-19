package notary

import (
	"strings"
	"testing"
	"time"
)

func TestJWSSigningAndVerification(t *testing.T) {
	ts := NewJWSTrustStore("https://controlplane.bap.internal", "https://gateway.bap.internal", "secret-test-key-12345")

	claims := JWSClaims{
		Sub:       "spiffe://bap.internal/app/financial-reconciler/instance/agent-01",
		SessionID: "sess-test-99",
		TaskID:    "task-audit-01",
		AgentID:   "agent-finance-01",
		RiskTier:  "TIER_2_MEDIUM",
		Scopes:    []string{"ledger:read", "ledger:audit"},
	}

	token, err := ts.SignClaims(claims)
	if err != nil {
		t.Fatalf("failed to sign claims: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in compact JWS, got %d", len(parts))
	}

	// 1. Valid verification
	verified, err := ts.VerifyToken(token, "https://gateway.bap.internal")
	if err != nil {
		t.Fatalf("expected token verification to succeed, got: %v", err)
	}
	if verified.SessionID != "sess-test-99" || verified.RiskTier != "TIER_2_MEDIUM" {
		t.Fatalf("unexpected claim content in verified token: %+v", verified)
	}

	// 2. Tampered token rejection
	tampered := parts[0] + "." + parts[1] + "extra" + "." + parts[2]
	if _, err := ts.VerifyToken(tampered, ""); err == nil {
		t.Fatalf("expected tampered token to be rejected")
	}

	// 3. Wrong audience rejection
	if _, err := ts.VerifyToken(token, "https://rogue-service.internal"); err == nil {
		t.Fatalf("expected wrong audience verification to fail")
	}

	// 4. Expired token rejection
	expiredClaims := claims
	expiredClaims.Exp = time.Now().UTC().Unix() - 100 // 100s in past
	expiredClaims.Nbf = time.Now().UTC().Unix() - 200
	expiredToken, err := ts.SignClaims(expiredClaims)
	if err != nil {
		t.Fatalf("failed to sign expired claims: %v", err)
	}
	if _, err := ts.VerifyToken(expiredToken, ""); err == nil {
		t.Fatalf("expected expired token to be rejected")
	}

	// 5. Key rotation test: rotate key, old key should still verify, new token uses new kid
	ts.RotateKey("bap-key-2026-v2", "rotated-secret-999")
	newToken, err := ts.SignClaims(claims)
	if err != nil {
		t.Fatalf("failed to sign claims after rotation: %v", err)
	}
	// Verify old token still works (key transition overlap)
	if _, err := ts.VerifyToken(token, ""); err != nil {
		t.Fatalf("expected previous token to still verify during transition: %v", err)
	}
	// Verify new token works
	if _, err := ts.VerifyToken(newToken, ""); err != nil {
		t.Fatalf("expected new token to verify: %v", err)
	}

	// 6. JWKS response test
	jwks := ts.GetJWKS()
	if len(jwks.Keys) < 2 {
		t.Fatalf("expected at least 2 keys in JWKS after rotation, got %d", len(jwks.Keys))
	}
}
