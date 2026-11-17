package authz

import "bap-edge/pkg/types"

// signingSecretConfigured reports whether the engine has a grant-signing secret. There is
// deliberately no built-in default: a hardcoded fallback secret would let anyone who reads the
// source forge grants (BAP-926).
func (e *ZSPEngine) signingSecretConfigured() bool {
	return len(e.pepSecret) > 0
}

// SetPermissionPolicy installs the effective permission policy (default or signed override).
func (e *ZSPEngine) SetPermissionPolicy(p *PermissionPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy = p
}

func (e *ZSPEngine) effectivePolicy() (*PermissionPolicy, error) {
	e.mu.RLock()
	p := e.policy
	e.mu.RUnlock()
	if p != nil {
		return p, nil
	}
	return DefaultPermissionPolicy()
}

// InstallSignedPermissionPolicy validates srcPath and installs it as the HMAC-signed override
// for zspDir using the workstation PEP secret. Human-operator action (BAP-925).
func InstallSignedPermissionPolicy(zspDir, srcPath string) error {
	secret, err := loadOrCreatePEPSecret(zspDir)
	if err != nil {
		return err
	}
	return SignPermissionPolicyFile(zspDir, secret, srcPath)
}

// DelegationDevOverride marks an envelope minted while a human-activated developer override
// window is open. It satisfies the policy-tier "needs approval" gate only; it never satisfies the
// governance-escalation gate (policy:, grant:, admin:, bap:override, ...), which always needs a
// real out-of-band human approval.
const DelegationDevOverride = "dev_override"

// isOutOfBandApproved reports whether the envelope clears the policy-tier approval gate: either the
// human out-of-band delegation, or a dev-override delegation while the override window is still
// active (re-checked here, so a stale or replayed envelope cannot outlive the window).
func isOutOfBandApproved(env *types.TaskAuthorizationEnvelope) bool {
	switch env.AuthorizedBy.DelegationType {
	case "human_interactive_oob":
		return true
	case DelegationDevOverride:
		return DevOverrideActive != nil && DevOverrideActive()
	case DelegationAutoApprove:
		// BAP-1100: re-checked on every evaluation; never satisfies the governance gate.
		return AutoApproveActive != nil && AutoApproveActive()
	}
	return false
}
