package authz

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"bap-edge/pkg/types"
)

var (
	// ErrLLMPlanViolatesPolicyInvariant enforces that AI-recommended plans cannot override policy (BAP-914).
	ErrLLMPlanViolatesPolicyInvariant = errors.New("non-reliance invariant violated: AI-recommended permission plan attempts to bypass Cedar security invariants")
	// ErrDataSensitivityClearanceDenied is returned when data classification exceeds agent clearance (BAP-906).
	ErrDataSensitivityClearanceDenied = errors.New("sensitivity authorization denied: agent is not cleared for restricted data without step-up approval")
)

// IntentToPermissionPlanner implements intent-to-permission planning with policy narrowing (BAP-901 & BAP-902).
type IntentToPermissionPlanner struct {
	SensitivityPolicy map[types.SensitivityLevel][]string
}

// NewIntentToPermissionPlanner creates a planner configured with data sensitivity rules.
func NewIntentToPermissionPlanner() *IntentToPermissionPlanner {
	return &IntentToPermissionPlanner{
		SensitivityPolicy: map[types.SensitivityLevel][]string{
			types.SensitivityPublic:       {"read", "inspect"},
			types.SensitivityInternal:     {"read", "write", "test", "build"},
			types.SensitivityConfidential: {"read", "review"},
			types.SensitivityRestricted:   {"require_step_up_approval"},
		},
	}
}

// Plan translates declared intent into a least-privilege proposal and evaluates policy narrowing (BAP-901 & BAP-902).
func (p *IntentToPermissionPlanner) Plan(
	sessionID string,
	principalID string,
	declaredIntent string,
	requestedActions []string,
	requestedResources []string,
	classification types.SensitivityLevel,
) (*types.PermissionPlan, error) {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	planID := fmt.Sprintf("plan-%s-%s", time.Now().Format("150405"), hex.EncodeToString(b))

	if classification == "" {
		classification = types.SensitivityInternal
	}

	plan := &types.PermissionPlan{
		PlanID:             planID,
		SessionID:          sessionID,
		PrincipalID:        principalID,
		DeclaredIntent:     declaredIntent,
		RequestedActions:   requestedActions,
		RequestedResources: requestedResources,
		SensitivityLevel:   classification,
		Decision:           types.DecisionAllow,
		CreatedAt:          time.Now().UTC(),
	}

	// 1. Enforce Non-Reliance Invariant (BAP-914): AI plans cannot request forbidden targets
	if err := ValidateNonReliance(plan); err != nil {
		plan.Decision = types.DecisionDeny
		plan.DeterministicRule = "Cedar Invariant Hard Gate: Forbidden Credential or Bypass Target"
		return plan, err
	}

	// 2. Enforce Data Sensitivity-Aware Authorization (BAP-906)
	if classification == types.SensitivityRestricted {
		plan.Decision = types.DecisionRequireApproval
		plan.RequiresApproval = true
		plan.ApprovalTicketID = fmt.Sprintf("SNOW-REQ-%s", hex.EncodeToString(b[:4]))
		plan.DeterministicRule = "Sensitivity Gate: RESTRICTED customer data mandates ServiceNow step-up approval"
		return plan, nil
	}

	// 3. Enforce Policy Narrowing (BAP-902): Attenuate broad actions to least privilege
	approvedActions, approvedResources, narrowed, reason := p.applyNarrowing(declaredIntent, requestedActions, requestedResources)
	plan.ApprovedActions = approvedActions
	plan.ApprovedResources = approvedResources
	plan.NarrowingApplied = narrowed
	plan.NarrowingReason = reason

	if narrowed {
		plan.Decision = types.DecisionNarrow
		plan.DeterministicRule = "Cedar Least-Privilege Policy: Broad privileges attenuated to task scope"
	} else {
		plan.DeterministicRule = "Cedar Permit: Requested actions conform to declared task intent"
	}

	return plan, nil
}

// applyNarrowing narrows broad requested actions into least-privilege equivalents (BAP-902).
func (p *IntentToPermissionPlanner) applyNarrowing(
	intent string,
	actions []string,
	resources []string,
) ([]string, []string, bool, string) {
	intentUpper := strings.ToUpper(intent)
	narrowed := false
	var reasons []string

	var approvedActions []string
	for _, act := range actions {
		actLower := strings.ToLower(act)
		// If task is investigation/review/docs, attenuate write actions to read-only
		if (strings.Contains(intentUpper, "INVESTIGATION") || strings.Contains(intentUpper, "DOCUMENTATION") || strings.Contains(intentUpper, "AUDIT")) &&
			(strings.Contains(actLower, "write") || strings.Contains(actLower, "push") || strings.Contains(actLower, "delete")) {
			approvedActions = append(approvedActions, "repo:read")
			narrowed = true
			reasons = append(reasons, fmt.Sprintf("attenuated %s to read-only for read task", act))
		} else if actLower == "repo:*" || actLower == "admin:*" {
			// Broad wildcard narrowed to specific read or write task
			approvedActions = append(approvedActions, "repo:read", "repo:push")
			narrowed = true
			reasons = append(reasons, "broad wildcard scope narrowed to task-scoped repository access")
		} else {
			approvedActions = append(approvedActions, act)
		}
	}

	var approvedResources []string
	for _, res := range resources {
		resLower := strings.ToLower(res)
		if resLower == "repo://*" || resLower == "/*" || resLower == "workspace://*" {
			approvedResources = append(approvedResources, "workspace://current")
			narrowed = true
			reasons = append(reasons, "wildcard root resource narrowed to current workspace root")
		} else {
			approvedResources = append(approvedResources, res)
		}
	}

	return approvedActions, approvedResources, narrowed, strings.Join(reasons, "; ")
}

// ValidateNonReliance guarantees that security decisions cannot rely on untrusted AI outputs (BAP-914).
func ValidateNonReliance(plan *types.PermissionPlan) error {
	forbiddenSubstrings := []string{
		".env",
		".aws",
		".ssh",
		"id_rsa",
		"id_ed25519",
		"admin:org",
		"delete_repo",
		"raw_socket",
		"curl http://",
		"nc -l",
	}

	for _, act := range plan.RequestedActions {
		actLower := strings.ToLower(act)
		for _, f := range forbiddenSubstrings {
			if strings.Contains(actLower, f) {
				return fmt.Errorf("%w: action %q targets prohibited credential or exfiltration vector", ErrLLMPlanViolatesPolicyInvariant, act)
			}
		}
	}

	for _, res := range plan.RequestedResources {
		resLower := strings.ToLower(res)
		for _, f := range forbiddenSubstrings {
			if strings.Contains(resLower, f) {
				return fmt.Errorf("%w: resource %q targets protected credential store", ErrLLMPlanViolatesPolicyInvariant, res)
			}
		}
	}

	return nil
}
