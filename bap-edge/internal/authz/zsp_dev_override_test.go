package authz

import (
	"errors"
	"testing"
	"time"
)

// While a human-activated developer override window is open, policy-tier "needs approval" asks
// mint without a HITL request. Governance escalations and hard-deny tiers must NOT be unlocked.

func withDevOverride(t *testing.T, active bool) {
	t.Helper()
	orig := DevOverrideActive
	DevOverrideActive = func() bool { return active }
	t.Cleanup(func() { DevOverrideActive = orig })
}

func mintWithDelegation(t *testing.T, delegation string, actions []string) error {
	t.Helper()
	_, _, err := SubmitTaskEnvelopeWithDelegation(t.TempDir(), "sess-devov", "claude-code", "TASK_EXECUTION",
		"dev override regression", "dev override regression", actions, []string{escalationWorkspace}, "", delegation, 1, 300*time.Second)
	return err
}

func TestDevOverride_PolicyTierAsksMintWhileActive(t *testing.T) {
	withDevOverride(t, true)
	for _, act := range []string{"cli:python:exec", "git:push:write"} {
		if err := mintWithDelegation(t, DelegationDevOverride, []string{act}); err != nil {
			t.Errorf("%s: dev override should clear the policy-tier approval gate, got %v", act, err)
		}
	}
}

func TestDevOverride_InactiveWindowStillRequiresApproval(t *testing.T) {
	withDevOverride(t, false)
	if err := mintWithDelegation(t, DelegationDevOverride, []string{"cli:python:exec"}); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Fatalf("expired/inactive override must not clear the gate, got %v", err)
	}
	orig := DevOverrideActive
	DevOverrideActive = nil
	t.Cleanup(func() { DevOverrideActive = orig })
	if err := mintWithDelegation(t, DelegationDevOverride, []string{"cli:python:exec"}); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Fatalf("unwired override hook must fail closed, got %v", err)
	}
}

func TestDevOverride_ClaimWithoutDelegationDoesNothing(t *testing.T) {
	withDevOverride(t, true)
	// An ordinary prompt delegation is not upgraded by an open window; only the command layer sets dev_override.
	if err := mintWithDelegation(t, "human_interactive_prompt", []string{"cli:python:exec"}); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Fatalf("expected approval requirement without dev_override delegation, got %v", err)
	}
}

func TestDevOverride_NeverUnlocksGovernanceEscalation(t *testing.T) {
	withDevOverride(t, true)
	for _, act := range []string{"policy:write", "grant:elevate", "admin:users", "bap:override", "dev-override:on", "sudo:run"} {
		if err := mintWithDelegation(t, DelegationDevOverride, []string{act}); !errors.Is(err, ErrHighRiskApprovalRequired) {
			t.Errorf("%s: governance escalation must still need a real human, got %v", act, err)
		}
	}
}

func TestDevOverride_NeverUnlocksHardDeny(t *testing.T) {
	withDevOverride(t, true)
	for _, act := range []string{"aws:secretsmanager:read", "github:cli:secret", "credential:access"} {
		if err := mintWithDelegation(t, DelegationDevOverride, []string{act}); err == nil {
			t.Errorf("%s: hard-deny tier must hold under dev override", act)
		}
	}
}
