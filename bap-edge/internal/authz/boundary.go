package authz

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrTrustBoundaryViolation is returned when a command violates the customer-network boundary (BAP-913).
	ErrTrustBoundaryViolation = errors.New("trust boundary violation: centralized service cannot command direct execution or retrieve target secrets")
	// ErrTargetCredentialExfiltration is returned when a target secret attempt is detected across the boundary.
	ErrTargetCredentialExfiltration = errors.New("trust boundary violation: target credentials cannot cross the execution boundary into policy service")
)

// TrustBoundaryConfig defines explicit boundary rules between decision plane and local execution (BAP-913).
type TrustBoundaryConfig struct {
	EnforceCustomerNetworkIsolation bool
	AllowCentralRemoteExecution      bool // Invariant: must be false in zero-trust configuration
	AllowCentralSecretExtraction     bool // Invariant: must be false in zero-trust configuration
}

// DefaultTrustBoundaryConfig returns the production zero-trust boundary configuration.
func DefaultTrustBoundaryConfig() TrustBoundaryConfig {
	return TrustBoundaryConfig{
		EnforceCustomerNetworkIsolation: true,
		AllowCentralRemoteExecution:      false,
		AllowCentralSecretExtraction:     false,
	}
}

// ValidateCentralRequest verifies that a central control plane request does not attempt
// direct host execution or credential retrieval outside approved boundaries (BAP-913).
func ValidateCentralRequest(reqType string, targetResource string, cfg TrustBoundaryConfig) error {
	reqNorm := strings.ToLower(strings.TrimSpace(reqType))
	resNorm := strings.ToLower(strings.TrimSpace(targetResource))

	// Invariant 1: Central control plane cannot directly command local shell execution
	if reqNorm == "exec_command" || reqNorm == "remote_shell" || reqNorm == "run_script" {
		if !cfg.AllowCentralRemoteExecution {
			return fmt.Errorf("%w: direct execution requested by central policy service", ErrTrustBoundaryViolation)
		}
	}

	// Invariant 2: Central control plane cannot request target secrets or private keys
	if reqNorm == "get_secret" || reqNorm == "fetch_credentials" || reqNorm == "export_private_key" {
		if !cfg.AllowCentralSecretExtraction {
			return fmt.Errorf("%w: secret extraction requested for %s", ErrTargetCredentialExfiltration, targetResource)
		}
	}

	// Invariant 3: Check sensitive resource patterns in targets
	forbiddenTargets := []string{".env", ".aws", ".ssh", "id_rsa", "id_ed25519", "credentials.json", "private_key"}
	for _, f := range forbiddenTargets {
		if strings.Contains(resNorm, f) {
			return fmt.Errorf("%w: resource %s contains protected customer credential store", ErrTargetCredentialExfiltration, targetResource)
		}
	}

	return nil
}

// SanitizeBrokerEnv ensures target secrets are only injected at local execution points
// and scrubbed from ambient environments and log payloads (BAP-903 & BAP-913).
func SanitizeBrokerEnv(env []string) []string {
	var cleaned []string
	sensitivePrefixes := []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
		"BAP_ADMIN_TOKEN",
		"BAP_TARGET_SECRET",
	}

	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 0 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(parts[0]))
		sensitive := false
		for _, prefix := range sensitivePrefixes {
			if strings.HasPrefix(key, prefix) {
				sensitive = true
				break
			}
		}
		if !sensitive {
			cleaned = append(cleaned, e)
		}
	}
	return cleaned
}
