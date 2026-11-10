package authz

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrCentralExecutionForbidden enforces that the centralized control plane is a decision plane only (BAP-913).
	ErrCentralExecutionForbidden = errors.New("decision plane invariant: central policy service cannot directly execute target actions")
	// ErrCentralSecretForbidden enforces that target credentials remain strictly on customer networks / credential broker.
	ErrCentralSecretForbidden = errors.New("decision plane invariant: central policy service cannot retrieve raw customer target secrets")
)

// DecisionPlaneBoundary asserts that the control plane adheres to trust boundary separation (BAP-913).
type DecisionPlaneBoundary struct {
	IsCentralPolicyService bool
}

// NewDecisionPlaneBoundary creates a trust boundary verifier for the central control plane.
func NewDecisionPlaneBoundary() *DecisionPlaneBoundary {
	return &DecisionPlaneBoundary{
		IsCentralPolicyService: true,
	}
}

// CheckTargetActionExecution ensures the centralized policy service does not directly invoke target actions.
func (b *DecisionPlaneBoundary) CheckTargetActionExecution(targetAction string) error {
	if b.IsCentralPolicyService {
		return fmt.Errorf("%w: attempted direct execution of action %s", ErrCentralExecutionForbidden, targetAction)
	}
	return nil
}

// CheckSecretRetrieval ensures the centralized policy service cannot retrieve raw customer credentials.
func (b *DecisionPlaneBoundary) CheckSecretRetrieval(targetSecretName string) error {
	if b.IsCentralPolicyService {
		sensitiveTerms := []string{"key", "token", "secret", "password", "credential", "private"}
		nameLower := strings.ToLower(targetSecretName)
		for _, term := range sensitiveTerms {
			if strings.Contains(nameLower, term) {
				return fmt.Errorf("%w: attempted retrieval of %s", ErrCentralSecretForbidden, targetSecretName)
			}
		}
	}
	return nil
}
