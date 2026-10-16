package authz

import (
	"testing"
	"time"
)

func TestSaaSTokenManager_BindingAndVerification(t *testing.T) {
	mgr := NewSaaSTokenManager()

	// 1. Bind token to session "sess-salesforce-001"
	binding, err := mgr.BindToken("salesforce", "tok-sf-123", "sess-salesforce-001", "agent-crm", "alice@corp.internal", []string{"crm:read", "lead:write"}, 10*time.Minute)
	if err != nil {
		t.Fatalf("Failed to bind SaaS token: %v", err)
	}

	if binding.TokenID != "tok-sf-123" {
		t.Errorf("Expected token ID tok-sf-123, got %s", binding.TokenID)
	}

	// 2. Legitimate verification within bound session
	ok, reason, err := mgr.VerifyUsage("tok-sf-123", "sess-salesforce-001", "crm:read")
	if !ok || err != nil {
		t.Fatalf("Expected token usage inside bound session to be authorized, got error: %v (reason: %s)", err, reason)
	}

	// 3. Violation: Attempting to use token in different session
	okDiff, reasonDiff, errDiff := mgr.VerifyUsage("tok-sf-123", "sess-attacker-999", "crm:read")
	if okDiff || errDiff == nil {
		t.Fatalf("Expected session binding violation when used from different session, but succeeded!")
	}
	if reasonDiff != "SessionBindingViolation" {
		t.Errorf("Expected reason SessionBindingViolation, got %s", reasonDiff)
	}

	// 4. Violation: Scope exceeded
	okScope, _, errScope := mgr.VerifyUsage("tok-sf-123", "sess-salesforce-001", "admin:delete_all")
	if okScope || errScope == nil {
		t.Fatalf("Expected scope exceeded error for admin:delete_all")
	}

	// 5. Revocation
	if err := mgr.RevokeToken("tok-sf-123", "Compromised credential reported"); err != nil {
		t.Fatal(err)
	}
	okRev, _, errRev := mgr.VerifyUsage("tok-sf-123", "sess-salesforce-001", "crm:read")
	if okRev || errRev == nil {
		t.Fatalf("Expected revoked token to be blocked")
	}
}
