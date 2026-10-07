package authz

import (
	"strings"
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

func TestVerifyAttenuation_Scopes(t *testing.T) {
	parentScopes := []string{"fs:read", "fs:write", "api:read"}

	// Valid subset
	childScopesValid := []string{"fs:read", "api:read"}
	if err := VerifyAttenuation(parentScopes, childScopesValid, "", "", "", ""); err != nil {
		t.Fatalf("expected valid subset to pass, got: %v", err)
	}

	// Invalid broader scope
	childScopesEscalated := []string{"fs:read", "admin:all"}
	err := VerifyAttenuation(parentScopes, childScopesEscalated, "", "", "", "")
	if err == nil {
		t.Fatalf("expected error for escalated scope, got nil")
	}
	if !strings.Contains(err.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked error, got: %v", err)
	}
}

func TestVerifyAttenuation_ResourceAndAction(t *testing.T) {
	// Sub-resource is allowed
	err := VerifyAttenuation(nil, nil, "/workspace/docs/*", "/workspace/docs/report.txt", "GET", "GET")
	if err != nil {
		t.Fatalf("expected sub-resource to be allowed, got: %v", err)
	}

	// Broadened resource to wildcard is blocked
	err = VerifyAttenuation(nil, nil, "/workspace/docs/*", "*", "GET", "GET")
	if err == nil || !strings.Contains(err.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked for wildcard resource, got: %v", err)
	}

	// Out of boundary resource is blocked
	err = VerifyAttenuation(nil, nil, "/workspace/docs/*", "/etc/passwd", "GET", "GET")
	if err == nil || !strings.Contains(err.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked for /etc/passwd, got: %v", err)
	}

	// Broadened action is blocked
	err = VerifyAttenuation(nil, nil, "", "", "GET", "POST")
	if err == nil || !strings.Contains(err.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked for action mismatch, got: %v", err)
	}
}

func TestDelegateAttenuatedChild_SuccessAndRevocation(t *testing.T) {
	secret := "test-secret-key-for-bap-minter-32b!"
	minter := NewTokenMinter(secret, 10*time.Minute)

	parentAgent := &types.RegisteredAgent{
		AgentID:         "root-orchestrator",
		AgentName:       "Root Orchestrator",
		AppID:           "claude-code",
		PermittedScopes: []string{"fs:read", "fs:write", "api:read"},
	}

	parentToken, _, parentGrantID, err := minter.MintWithDetails(
		parentAgent,
		"hash-1",
		[]string{"fs:read", "fs:write", "api:read"},
		"sess-parent",
		"exec",
		"/workspace/*",
		nil,
		"v1",
	)
	if err != nil {
		t.Fatalf("failed to mint parent token: %v", err)
	}

	childAgent := &types.RegisteredAgent{
		AgentID:   "subagent-researcher",
		AgentName: "Subagent Researcher",
		AppID:     "claude-subagent",
	}

	// 1. Valid child delegation: narrower scopes
	childToken, _, childGrantID, childClaims, err := minter.DelegateAttenuatedChild(
		parentToken,
		childAgent,
		[]string{"fs:read"},
		"sess-child-1",
		"exec",
		"/workspace/research/*",
		nil,
		5,
	)
	if err != nil {
		t.Fatalf("failed to delegate attenuated child grant: %v", err)
	}

	if childClaims.ParentGrantID != parentGrantID {
		t.Fatalf("expected ParentGrantID %s, got %s", parentGrantID, childClaims.ParentGrantID)
	}
	if childClaims.RootAgentID != "root-orchestrator" {
		t.Fatalf("expected RootAgentID 'root-orchestrator', got %s", childClaims.RootAgentID)
	}
	if len(childClaims.Lineage) != 2 || childClaims.Lineage[0] != "root-orchestrator" || childClaims.Lineage[1] != "subagent-researcher" {
		t.Fatalf("unexpected lineage: %v", childClaims.Lineage)
	}
	expectedTree := "root-orchestrator -> subagent-researcher"
	if childClaims.LineageTree != expectedTree {
		t.Fatalf("expected lineage tree %q, got %q", expectedTree, childClaims.LineageTree)
	}

	// Verify child token succeeds
	verifiedClaims, err := minter.Verify(childToken)
	if err != nil {
		t.Fatalf("failed to verify child token: %v", err)
	}
	if verifiedClaims.GrantID != childGrantID {
		t.Fatalf("expected grant ID %s, got %s", childGrantID, verifiedClaims.GrantID)
	}

	// 2. Grandchild delegation
	workerAgent := &types.RegisteredAgent{
		AgentID:   "worker-parser",
		AgentName: "Worker Parser",
		AppID:     "worker-tool",
	}
	workerToken, _, workerGrantID, workerClaims, err := minter.DelegateAttenuatedChild(
		childToken,
		workerAgent,
		[]string{"fs:read"},
		"sess-worker-1",
		"exec",
		"/workspace/research/docs/*",
		nil,
		3,
	)
	if err != nil {
		t.Fatalf("failed to delegate grandchild: %v", err)
	}
	expectedWorkerTree := "root-orchestrator -> subagent-researcher -> worker-parser"
	if workerClaims.LineageTree != expectedWorkerTree {
		t.Fatalf("expected worker lineage tree %q, got %q", expectedWorkerTree, workerClaims.LineageTree)
	}

	// Verify worker token works
	if _, err := minter.Verify(workerToken); err != nil {
		t.Fatalf("failed to verify worker token: %v", err)
	}

	// 3. Escalation attempt: Child requesting broader scope than parent
	_, _, _, _, err = minter.DelegateAttenuatedChild(
		parentToken,
		childAgent,
		[]string{"fs:read", "admin:all"}, // admin:all is not in parent grant!
		"sess-child-2",
		"exec",
		"/workspace/*",
		nil,
		5,
	)
	if err == nil {
		t.Fatalf("expected escalation error, got nil")
	}
	if !strings.Contains(err.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked error, got: %v", err)
	}

	// 4. Cascading Revocation: Revoking root parent grant immediately revokes all descendant grants
	revoked := minter.RevokeGrant(parentGrantID, "Administrator revoked root orchestrator")
	if len(revoked) < 3 {
		t.Fatalf("expected at least 3 grants revoked in cascade, got: %v", revoked)
	}

	if isRev, _ := minter.IsGrantRevoked(childGrantID); !isRev {
		t.Fatalf("expected child grant to be revoked via cascade")
	}
	if isRev, _ := minter.IsGrantRevoked(workerGrantID); !isRev {
		t.Fatalf("expected worker grant to be revoked via cascade")
	}

	// Verification of child and grandchild tokens now fails closed
	if _, err := minter.Verify(childToken); err == nil {
		t.Fatalf("expected child token verification to fail after parent revocation, got nil")
	}
	if _, err := minter.Verify(workerToken); err == nil {
		t.Fatalf("expected worker token verification to fail after root revocation, got nil")
	}
}
