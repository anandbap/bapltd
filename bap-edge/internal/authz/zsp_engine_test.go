package authz

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/identity"
	"bap-edge/pkg/types"
)

// TestBAP915_CryptographicAgentIdentityMintingAndVerification verifies that an agent
// receives an ephemeral keypair and an authentic, signed SVID tied to human identity (BAP-915).
func TestBAP915_CryptographicAgentIdentityMintingAndVerification(t *testing.T) {
	minter := identity.NewWorkstationIdentityMinter("test-ca-secret-key-32-bytes-long!", "bap.corp.local")

	kp, err := identity.GenerateAgentKeypair()
	if err != nil {
		t.Fatalf("Failed to generate agent keypair: %v", err)
	}

	svid, err := minter.MintAgentSVID(
		kp,
		"alice@corp.com",
		"entra|user-guid-12345",
		"workstation-laptop-01",
		"sess-claude-915",
		"claude-code",
		1*time.Hour,
	)
	if err != nil {
		t.Fatalf("Failed to mint SVID: %v", err)
	}

	// 1. Verify valid SVID
	if err := minter.VerifyAgentSVID(svid); err != nil {
		t.Errorf("Expected valid SVID, got error: %v", err)
	}
	if svid.HumanOwner != "alice@corp.com" {
		t.Errorf("Expected HumanOwner alice@corp.com, got %s", svid.HumanOwner)
	}

	// 2. Tampered SVID signature must fail
	tampered := *svid
	tampered.HumanOwner = "attacker@evil.com"
	if err := minter.VerifyAgentSVID(&tampered); err != identity.ErrTamperedAgentSVID {
		t.Errorf("Expected ErrTamperedAgentSVID for altered human owner, got %v", err)
	}

	// 3. Expired SVID must fail
	expired := *svid
	expired.ExpiresAt = time.Now().UTC().Add(-10 * time.Minute)
	if err := minter.VerifyAgentSVID(&expired); err != identity.ErrExpiredAgentSVID {
		t.Errorf("Expected ErrExpiredAgentSVID for expired SVID, got %v", err)
	}
}

// TestBAP916_Atomic4TupleTaskAuthorizationEnvelope verifies that the 4-tuple envelope
// (Who, AuthorizedBy, Intent, PermissionAsk) is signed by the agent's keypair (BAP-916).
func TestBAP916_Atomic4TupleTaskAuthorizationEnvelope(t *testing.T) {
	minter := identity.NewWorkstationIdentityMinter("test-ca-secret-key-32-bytes-long!", "bap.corp.local")
	kp, _ := identity.GenerateAgentKeypair()
	svid, _ := minter.MintAgentSVID(kp, "alice@corp.com", "entra|123", "ws-01", "sess-01", "claude-code", time.Hour)

	del := types.DelegationIdentity{
		DelegationType: "human_interactive_prompt",
		ApproverEmail:  "alice@corp.com",
	}
	intent := types.TaskIntent{
		PrimaryMission: "BUG_FIX",
		DeclaredGoal:   "Fix authentication issue",
		PromptHash:     "sha256:11223344",
	}
	perms := types.PermissionAsk{
		Actions:   []string{"git:diff", "fs:read"},
		Resources: []string{"workspace://src/**"},
	}

	hashStr := identity.ComputeEnvelopeHash(*svid, del, intent, perms)
	hashBytes, _ := hex.DecodeString(hashStr)
	sig := kp.Sign(hashBytes)

	env := &types.TaskAuthorizationEnvelope{
		EnvelopeID:     "env-001",
		Identity:       *svid,
		AuthorizedBy:   del,
		Intent:         intent,
		PermissionAsk:  perms,
		EnvelopeHash:   hashStr,
		AgentSignature: hex.EncodeToString(sig),
		Timestamp:      time.Now().UTC(),
	}

	// 1. Valid envelope signature verification
	if err := identity.VerifyEnvelopeSignature(env); err != nil {
		t.Errorf("Expected envelope signature to verify cleanly, got %v", err)
	}

	// 2. Tampered envelope (modified permission ask) must fail signature verification
	tamperedEnv := *env
	tamperedEnv.PermissionAsk.Actions = []string{"rm -rf /"}
	// Note: Hash does not match signature or recomputed hash
	tamperedEnv.EnvelopeHash = identity.ComputeEnvelopeHash(*svid, del, intent, tamperedEnv.PermissionAsk)
	if err := identity.VerifyEnvelopeSignature(&tamperedEnv); err != identity.ErrInvalidAgentSignature {
		t.Errorf("Expected ErrInvalidAgentSignature for tampered envelope, got %v", err)
	}
}

// TestBAP917_ZeroStandingPrivilegesAndJITTaskGrants verifies that starting permissions
// are strictly zero, grants are attenuated, single-use, and burned upon execution (BAP-917).
func TestBAP917_ZeroStandingPrivilegesAndJITTaskGrants(t *testing.T) {
	minter := identity.NewWorkstationIdentityMinter("test-ca-secret-key-32-bytes-long!", "bap.corp.local")
	engine := NewZSPEngine(minter, "pep-secret-key-test")

	// 1. Starting permissions = 0: Execution without grant MUST FAIL
	_, err := engine.ConsumeTaskGrant("", "git:diff", "workspace://current", "git diff", []string{"parent", "broker"})
	if err != ErrZeroStandingPrivilegeViolation {
		t.Errorf("Expected ErrZeroStandingPrivilegeViolation when no grant is provided, got %v", err)
	}

	// 2. Submit valid 4-tuple envelope
	kp, _ := identity.GenerateAgentKeypair()
	svid, _ := minter.MintAgentSVID(kp, "alice@corp.com", "entra|123", "ws-01", "sess-42", "claude-code", time.Hour)
	del := types.DelegationIdentity{DelegationType: "human_interactive_prompt"}
	intent := types.TaskIntent{PrimaryMission: "BUG_FIX", DeclaredGoal: "Inspect repo", PromptHash: "sha256:abc"}
	perms := types.PermissionAsk{Actions: []string{"git:diff", "repo:*"}, Resources: []string{"workspace://current"}}

	hashStr := identity.ComputeEnvelopeHash(*svid, del, intent, perms)
	hashBytes, _ := hex.DecodeString(hashStr)
	sig := kp.Sign(hashBytes)

	env := &types.TaskAuthorizationEnvelope{
		EnvelopeID:     "env-test-42",
		Identity:       *svid,
		AuthorizedBy:   del,
		Intent:         intent,
		PermissionAsk:  perms,
		EnvelopeHash:   hashStr,
		AgentSignature: hex.EncodeToString(sig),
	}

	// 3. Issue single-use Task Grant (maxUses = 1)
	grant, err := engine.AuthorizeTaskEnvelope(env, 1, 300*time.Second)
	if err != nil {
		t.Fatalf("Failed to authorize envelope: %v", err)
	}

	if grant.RemainingUses != 1 || grant.IsBurned {
		t.Fatalf("Expected fresh grant with RemainingUses=1, got %d (burned=%v)", grant.RemainingUses, grant.IsBurned)
	}

	// 4. Attempt ungranted destructive action -> MUST FAIL
	_, err = engine.ConsumeTaskGrant(grant.GrantID, "rm -rf /", "workspace://current", "rm -rf /", nil)
	if err == nil {
		t.Errorf("Expected error for ungranted action, got allowed")
	}

	// 5. Execute granted action -> SUCCESS
	proof, err := engine.ConsumeTaskGrant(grant.GrantID, "git:diff", "workspace://current", "git diff", []string{"claude", "bapedge"})
	if err != nil {
		t.Fatalf("Failed to consume valid grant: %v", err)
	}
	if proof.DecisionResult != "ALLOWED_EXECUTED" {
		t.Errorf("Expected ALLOWED_EXECUTED, got %s", proof.DecisionResult)
	}

	// 6. Second execution with burned single-use grant -> MUST FAIL (Anti-Replay / ZSP)
	_, err = engine.ConsumeTaskGrant(grant.GrantID, "git:diff", "workspace://current", "git diff", []string{"claude", "bapedge"})
	if err != ErrGrantBurned {
		t.Errorf("Expected ErrGrantBurned for consumed single-use grant, got %v", err)
	}
}

// TestBAP918_CryptographicAuditLineageAndNonRepudiation verifies that the execution
// receipt mathematically proves Human -> Agent Key -> Intent -> Grant -> Execution (BAP-918).
func TestBAP918_CryptographicAuditLineageAndNonRepudiation(t *testing.T) {
	minter := identity.NewWorkstationIdentityMinter("test-ca-secret-key-32-bytes-long!", "bap.corp.local")
	engine := NewZSPEngine(minter, "pep-secret-key-test")

	kp, _ := identity.GenerateAgentKeypair()
	svid, _ := minter.MintAgentSVID(kp, "alice@corp.com", "entra|user-42", "ws-finance", "sess-fin-1", "claude-code", time.Hour)
	del := types.DelegationIdentity{DelegationType: "human_interactive_prompt"}
	intent := types.TaskIntent{PrimaryMission: "INVESTIGATION", DeclaredGoal: "Review ledger changes", PromptHash: "sha256:7788"}
	perms := types.PermissionAsk{Actions: []string{"git:inspect:read"}, Resources: []string{"workspace://current"}}

	hashStr := identity.ComputeEnvelopeHash(*svid, del, intent, perms)
	hashBytes, _ := hex.DecodeString(hashStr)
	sig := kp.Sign(hashBytes)

	env := &types.TaskAuthorizationEnvelope{
		EnvelopeID:     "env-fin-01",
		Identity:       *svid,
		AuthorizedBy:   del,
		Intent:         intent,
		PermissionAsk:  perms,
		EnvelopeHash:   hashStr,
		AgentSignature: hex.EncodeToString(sig),
	}

	grant, _ := engine.AuthorizeTaskEnvelope(env, 1, 300*time.Second)

	proof, err := engine.ConsumeTaskGrant(grant.GrantID, "git:inspect:read", "workspace://current", "git log -n 5", []string{"parent", "broker", "child"})
	if err != nil {
		t.Fatalf("ConsumeTaskGrant failed: %v", err)
	}

	// Auditor verifies non-repudiation chain
	if proof.HumanOwner != "alice@corp.com" {
		t.Errorf("Lineage broken: human owner expected alice@corp.com, got %s", proof.HumanOwner)
	}
	if proof.AgentPrincipalSVID != svid.Subject {
		t.Errorf("Lineage broken: agent SVID mismatch")
	}
	if proof.GrantID != grant.GrantID {
		t.Errorf("Lineage broken: grant ID mismatch")
	}
	if proof.CommandExecuted != "git log -n 5" {
		t.Errorf("Lineage broken: command executed mismatch")
	}
	if proof.LedgerSignature == "" {
		t.Errorf("Missing cryptographic ledger signature for non-repudiation")
	}
}

func TestAuthorizeTaskEnvelopeBlocksHighRiskEscalationWithoutOOBApproval(t *testing.T) {
	zspDir := t.TempDir()
	_, _, err := SubmitTaskEnvelope(
		zspDir, "sess-esc-1", "claude-code", "TASK_EXECUTION",
		"Request privilege escalation", "Demonstrate high-risk gate",
		[]string{"policy:write", "grant:elevate"}, []string{"workspace://current"},
		"", 1, 300*time.Second,
	)
	if err == nil {
		t.Fatal("expected ErrHighRiskApprovalRequired for autonomous policy:write/grant:elevate ask, got nil")
	}
	if !strings.Contains(err.Error(), "out-of-band interactive human approval") {
		t.Fatalf("expected out-of-band approval error, got: %v", err)
	}

	grant, _, err := SubmitTaskEnvelopeWithDelegation(
		zspDir, "sess-esc-1", "claude-code", "TASK_EXECUTION",
		"Human-approved escalation", "Human approved out-of-band",
		[]string{"policy:write", "grant:elevate"}, []string{"workspace://current"},
		"", "human_interactive_oob", 1, 300*time.Second,
	)
	if err != nil {
		t.Fatalf("expected human_interactive_oob escalation to succeed, got: %v", err)
	}
	if grant == nil || len(grant.AllowedActions) != 2 {
		t.Fatalf("unexpected grant after oob approval: %+v", grant)
	}
}

func TestAuthorizeTaskEnvelopeMarksNarrowingApplied(t *testing.T) {
	zspDir := t.TempDir()
	grant, _, err := SubmitTaskEnvelope(
		zspDir, "sess-narrow-1", "claude-code", "TASK_EXECUTION",
		"Broad repo ask", "Request repo:*",
		[]string{"repo:*"}, []string{"workspace://current"},
		"", 5, 300*time.Second,
	)
	if err != nil {
		t.Fatalf("SubmitTaskEnvelope failed: %v", err)
	}
	if !grant.NarrowingApplied {
		t.Fatalf("expected NarrowingApplied=true for repo:*, got false")
	}
	if len(grant.RequestedActions) != 1 || grant.RequestedActions[0] != "repo:*" {
		t.Fatalf("expected RequestedActions=[repo:*], got %v", grant.RequestedActions)
	}
	if len(grant.AllowedActions) != 2 || grant.AllowedActions[0] != "repo:read" || grant.AllowedActions[1] != "repo:push" {
		t.Fatalf("expected attenuated AllowedActions=[repo:read repo:push], got %v", grant.AllowedActions)
	}
	if grant.NarrowingReason == "" {
		t.Fatalf("expected non-empty NarrowingReason")
	}
}
