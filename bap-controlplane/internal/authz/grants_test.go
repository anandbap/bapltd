package authz

import (
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

func TestRequestedScopesCannotEscalateAuthority(t *testing.T) {
	minter := NewTokenMinter("test-secret", time.Minute)
	agent := &types.RegisteredAgent{AgentID: "scoped-agent", PermittedScopes: []string{"api:read"}}
	for _, scope := range []string{"*", "api:write", "cli:exec"} {
		if _, _, err := minter.Mint(agent, "hash", []string{scope}); err == nil {
			t.Fatalf("scope escalation accepted: %s", scope)
		}
	}
	token, _, err := minter.Mint(agent, "hash", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := minter.Consume(token, "cli:exec"); err == nil {
		t.Fatal("cli:exec bypassed scope validation")
	}
}

func TestTokenMinter_MintAndVerify(t *testing.T) {
	secret := "test-secret-key-very-secure-12345"
	minter := NewTokenMinter(secret, 10*time.Minute)

	agent := &types.RegisteredAgent{
		AgentID:         "agent-unit-test",
		AppID:           "test-app",
		AgentName:       "TestAgent",
		EnvProfile:      types.ProfileDev,
		PermittedScopes: []string{"cli:exec", "git:read"},
	}

	token, exp, err := minter.Mint(agent, "sha256-hash-abc", []string{"cli:exec"})
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	if exp.Before(time.Now()) {
		t.Fatalf("expected expiration in future")
	}

	claims, err := minter.Verify(token)
	if err != nil {
		t.Fatalf("failed to verify valid token: %v", err)
	}

	if claims.Sub != agent.AgentID {
		t.Errorf("expected Sub %s, got %s", agent.AgentID, claims.Sub)
	}
	if claims.AppID != agent.AppID {
		t.Errorf("expected AppID %s, got %s", agent.AppID, claims.AppID)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "cli:exec" {
		t.Errorf("expected requested scope cli:exec, got %v", claims.Scopes)
	}
}

func TestTokenMinter_InvalidSignature(t *testing.T) {
	minter1 := NewTokenMinter("secret-one", 10*time.Minute)
	minter2 := NewTokenMinter("secret-two", 10*time.Minute)

	agent := &types.RegisteredAgent{AgentID: "agent-tamper"}
	token, _, err := minter1.Mint(agent, "hash", nil)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Verify with wrong key
	_, err = minter2.Verify(token)
	if err == nil {
		t.Fatalf("expected verification to fail with different secret key")
	}
}

func TestTokenMinter_Consume(t *testing.T) {
	minter := NewTokenMinter("secret-test-consume", 10*time.Minute)
	agent := &types.RegisteredAgent{
		AgentID:         "agent-consumer",
		AppID:           "test-app",
		PermittedScopes: []string{"payments:charge"},
	}

	token, _, err := minter.Mint(agent, "some-hash", []string{"payments:charge"})
	if err != nil {
		t.Fatalf("failed to mint: %v", err)
	}

	// 1. Consume with matching scope -> Succeeded
	claims, err := minter.Consume(token, "payments:charge")
	if err != nil {
		t.Fatalf("expected valid consume, got: %v", err)
	}
	if claims.Sub != agent.AgentID {
		t.Errorf("expected agent ID %s, got %s", agent.AgentID, claims.Sub)
	}

	// 2. Consume again (replay) -> Fails
	_, err = minter.Consume(token, "payments:charge")
	if err == nil {
		t.Fatalf("expected replay consumption to fail")
	}

	// 3. Consume with unauthorized scope
	token2, _, _ := minter.Mint(agent, "some-hash", []string{"payments:charge"})
	_, err = minter.Consume(token2, "admin:delete")
	if err == nil {
		t.Fatalf("expected unauthorized scope to fail")
	}
}

func TestVerifyAttenuation_MonotonicSubset(t *testing.T) {
	// 1. Child with subset scopes -> ALLOW
	err := VerifyAttenuation([]string{"fs:read", "fs:write"}, []string{"fs:read"}, "repo/src", "repo/src/main.go", "read", "read")
	if err != nil {
		t.Fatalf("expected valid subset attenuation to pass, got: %v", err)
	}

	// 2. Child attempting scope escalation -> BLOCKED
	errEscalation := VerifyAttenuation([]string{"fs:read"}, []string{"fs:read", "admin:all"}, "", "", "", "")
	if errEscalation == nil {
		t.Fatal("expected scope escalation to be blocked")
	}

	// 3. Child attempting resource widening -> BLOCKED
	errResourceWidening := VerifyAttenuation([]string{"fs:read"}, []string{"fs:read"}, "repo/src", "repo", "read", "read")
	if errResourceWidening == nil {
		t.Fatal("expected resource widening to be blocked")
	}

	// 4. Child attempting action broadening -> BLOCKED
	errActionBroadening := VerifyAttenuation([]string{"fs:read"}, []string{"fs:read"}, "repo/src", "repo/src", "read", "write")
	if errActionBroadening == nil {
		t.Fatal("expected action broadening to be blocked")
	}
}

func TestDelegateAttenuatedChild_LineageAndRevocation(t *testing.T) {
	minter := NewTokenMinter("secret-test-delegation", 30*time.Minute)
	parentAgent := &types.RegisteredAgent{
		AgentID:         "orchestrator-root",
		AppID:           "test-app",
		PermittedScopes: []string{"git:read", "git:write"},
	}

	// Mint parent grant
	parentToken, _, parentGrantID, err := minter.MintWithDetails(parentAgent, "parent-hash", []string{"git:read", "git:write"}, "sess-parent", "git:read", "repo/path", nil, "v1")
	if err != nil {
		t.Fatalf("failed to mint parent grant: %v", err)
	}

	// Delegate to child subagent with attenuated scope "git:read"
	childAgent := &types.RegisteredAgent{
		AgentID:    "worker-subagent-1",
		AppID:      "test-app",
		AgentName:  "WorkerSubagent",
		EnvProfile: types.ProfileDev,
	}
	childToken, _, childGrantID, childClaims, err := minter.DelegateAttenuatedChild(parentToken, childAgent, []string{"git:read"}, "sess-child", "git:read", "repo/path", nil, 10)
	if err != nil {
		t.Fatalf("expected successful child delegation, got: %v", err)
	}

	if childClaims.ParentGrantID != parentGrantID {
		t.Errorf("expected parent grant ID %s, got %s", parentGrantID, childClaims.ParentGrantID)
	}
	if childClaims.LineageTree != "orchestrator-root -> worker-subagent-1" {
		t.Errorf("expected lineage tree 'orchestrator-root -> worker-subagent-1', got %s", childClaims.LineageTree)
	}

	// Verify child token is valid initially
	if isRevoked, _ := minter.IsGrantRevoked(childGrantID); isRevoked {
		t.Fatal("child grant should not be revoked yet")
	}

	// Cascading Revocation: Revoke parent grant
	revoked := minter.RevokeGrant(parentGrantID, "Compromise detected in parent")
	if len(revoked) < 2 {
		t.Errorf("expected cascading revocation of parent and child, revoked: %v", revoked)
	}

	// Verify child grant is now revoked
	if isRevoked, _ := minter.IsGrantRevoked(childGrantID); !isRevoked {
		t.Fatal("child grant MUST be revoked when parent grant is revoked")
	}
	_ = childToken
}

