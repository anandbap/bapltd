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

// isOutOfBandApproved reports whether the envelope carries the human out-of-band delegation.
func isOutOfBandApproved(env *types.TaskAuthorizationEnvelope) bool {
	return env.AuthorizedBy.DelegationType == "human_interactive_oob"
}
