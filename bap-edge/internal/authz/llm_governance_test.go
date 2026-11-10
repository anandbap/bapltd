package authz

import (
	"strings"
	"testing"

	"bap-edge/pkg/types"
)

// TestBAP901_IntentToPermissionPlanning verifies that declared intent is translated
// into a least-privilege proposal and AI-generated plans cannot override policy (BAP-901).
func TestBAP901_IntentToPermissionPlanning(t *testing.T) {
	planner := NewIntentToPermissionPlanner()

	// Claude Code requests broad repository access
	plan, err := planner.Plan(
		"sess-test-claude",
		"urn:bap:principal:agent:claude-01",
		"BUG_FIX: Fix login bug",
		[]string{"repo:*"},
		[]string{"workspace://*"},
		types.SensitivityInternal,
	)
	if err != nil {
		t.Fatalf("Unexpected plan error: %v", err)
	}

	if plan.Decision != types.DecisionNarrow {
		t.Errorf("Expected DecisionNarrow for broad wildcard request, got %v", plan.Decision)
	}
	if !plan.NarrowingApplied {
		t.Errorf("Expected NarrowingApplied == true")
	}

	// Verify broad repo:* was narrowed to specific permissions
	foundWildcard := false
	for _, act := range plan.ApprovedActions {
		if act == "repo:*" {
			foundWildcard = true
		}
	}
	if foundWildcard {
		t.Errorf("Broad wildcard repo:* should not be in ApprovedActions")
	}
}

// TestBAP902_PolicyNarrowingAndConditionalAuthorization verifies that an agent requesting
// production write access during an investigation task is narrowed to read-only (BAP-902).
func TestBAP902_PolicyNarrowingAndConditionalAuthorization(t *testing.T) {
	planner := NewIntentToPermissionPlanner()

	// Agent declares INVESTIGATION task but requests write and delete permissions
	plan, err := planner.Plan(
		"sess-test-investigation",
		"urn:bap:principal:agent:claude-02",
		"INVESTIGATION: Analyze production crash log",
		[]string{"repo:write", "repo:delete"},
		[]string{"file://logs"},
		types.SensitivityInternal,
	)
	if err != nil {
		t.Fatalf("Unexpected plan error: %v", err)
	}

	if plan.Decision != types.DecisionNarrow {
		t.Errorf("Expected DecisionNarrow, got %v", plan.Decision)
	}

	for _, act := range plan.ApprovedActions {
		if act == "repo:write" || act == "repo:delete" {
			t.Errorf("Dangerous action %q was not attenuated for INVESTIGATION task", act)
		}
	}
	if len(plan.ApprovedActions) == 0 || plan.ApprovedActions[0] != "repo:read" {
		t.Errorf("Expected attenuated action repo:read, got %v", plan.ApprovedActions)
	}
}

// TestBAP906_DataSensitivityAwareAuthorization verifies that data classification
// influences permissions issued to agents and restricts restricted customer data (BAP-906).
func TestBAP906_DataSensitivityAwareAuthorization(t *testing.T) {
	planner := NewIntentToPermissionPlanner()

	// Agent authorized to read internal documentation attempts restricted customer data
	plan, err := planner.Plan(
		"sess-test-sensitive",
		"urn:bap:principal:agent:claude-03",
		"FEATURE_ENHANCEMENT: Export customer accounts",
		[]string{"customer_db:read"},
		[]string{"db://prod/customer_pii"},
		types.SensitivityRestricted, // Restricted classification
	)
	if err != nil {
		t.Fatalf("Unexpected plan error: %v", err)
	}

	if plan.Decision != types.DecisionRequireApproval {
		t.Errorf("Expected DecisionRequireApproval for RESTRICTED sensitivity, got %v", plan.Decision)
	}
	if !plan.RequiresApproval {
		t.Errorf("Expected RequiresApproval == true")
	}
	if !strings.HasPrefix(plan.ApprovalTicketID, "SNOW-REQ-") {
		t.Errorf("Expected ServiceNow approval ticket ID, got %s", plan.ApprovalTicketID)
	}
}

// TestBAP913_CustomerNetworkCredentialAndEnforcementBoundary verifies explicit trust boundaries
// between decision plane, local execution infrastructure, and credential broker (BAP-913).
func TestBAP913_CustomerNetworkCredentialAndEnforcementBoundary(t *testing.T) {
	cfg := DefaultTrustBoundaryConfig()

	// 1. Central policy service attempts to command direct local shell execution -> MUST FAIL
	err := ValidateCentralRequest("exec_command", "powershell.exe -Command whoami", cfg)
	if err == nil {
		t.Errorf("Expected trust boundary violation for direct central execution, got nil")
	}

	// 2. Central policy service attempts to extract raw customer secrets -> MUST FAIL
	err = ValidateCentralRequest("fetch_credentials", "C:\\Users\\User\\.aws\\credentials", cfg)
	if err == nil {
		t.Errorf("Expected trust boundary violation for secret extraction, got nil")
	}

	// 3. Central policy service requests target credential store (.env) -> MUST FAIL
	err = ValidateCentralRequest("read_file", "project/.env", cfg)
	if err == nil {
		t.Errorf("Expected trust boundary violation for .env access, got nil")
	}

	// 4. Benign policy bundle sync -> PERMITTED
	err = ValidateCentralRequest("policy_sync", "policy.cedar", cfg)
	if err != nil {
		t.Errorf("Expected policy_sync to pass trust boundary check, got: %v", err)
	}

	// 5. Ambient credential scrubbing
	ambientEnv := []string{
		"PATH=/usr/bin",
		"AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLESECRET",
		"GITHUB_TOKEN=ghp_secretTokenHere",
		"WORKSPACE=C:\\project",
	}
	cleaned := SanitizeBrokerEnv(ambientEnv)
	for _, env := range cleaned {
		if strings.Contains(env, "AWS_SECRET_ACCESS_KEY") || strings.Contains(env, "GITHUB_TOKEN") {
			t.Errorf("Sensitive credential leaked through broker sanitization: %s", env)
		}
	}
	if len(cleaned) != 2 {
		t.Errorf("Expected 2 sanitized env entries, got %d", len(cleaned))
	}
}

// TestBAP914_LLMCallInventoryAndSecurityGovernance verifies that security-critical
// decisions cannot rely solely on untrusted LLM output (BAP-914).
func TestBAP914_LLMCallInventoryAndSecurityGovernance(t *testing.T) {
	planner := NewIntentToPermissionPlanner()

	// Adversarial LLM recommendation attempts to request .env access and raw socket exfiltration
	adversarialPlan := &types.PermissionPlan{
		PlanID:             "plan-adversarial-01",
		SessionID:          "sess-rogue",
		PrincipalID:        "urn:bap:principal:agent:claude-rogue",
		DeclaredIntent:     "BUG_FIX: Read config",
		RequestedActions:   []string{"fs:read", "nc -l 4444"},
		RequestedResources: []string{".env"},
		SensitivityLevel:   types.SensitivityInternal,
	}

	// Evaluate non-reliance invariant
	err := ValidateNonReliance(adversarialPlan)
	if err == nil {
		t.Fatalf("Expected non-reliance invariant violation for adversarial plan, got nil")
	}

	// Verify planner rejects adversarial intent proposal
	plan, err := planner.Plan(
		"sess-rogue",
		"urn:bap:principal:agent:claude-rogue",
		"Adversarial Task",
		[]string{"fs:read"},
		[]string{"../../.env"},
		types.SensitivityInternal,
	)
	if err == nil {
		t.Errorf("Expected planner to reject .env access proposal, got allowed")
	}
	if plan.Decision != types.DecisionDeny {
		t.Errorf("Expected DecisionDeny, got %v", plan.Decision)
	}
}
