package policy

import (
	"testing"
)

func TestValidateCedar(t *testing.T) {
	validPolicy := `
// Allow git status
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "git"
};
`
	res := ValidateCedar(validPolicy, "")
	if !res.Valid {
		t.Fatalf("expected valid policy, got errors: %v", res.Errors)
	}
	if res.PolicyCount != 1 {
		t.Fatalf("expected 1 policy, got %d", res.PolicyCount)
	}

	invalidPolicy := `
permit (
    principal == Agent::"Local"
    // Missing comma and action
    resource == Command::"CLI"
);
`
	resInvalid := ValidateCedar(invalidPolicy, "")
	if resInvalid.Valid {
		t.Fatalf("expected invalid policy to fail")
	}
	if len(resInvalid.Errors) == 0 {
		t.Fatalf("expected error diagnostics, got none")
	}
}

func TestSimulatePolicySandbox(t *testing.T) {
	currentPolicy := `
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "git"
};
`
	draftPolicy := `
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "git" || context.executable == "pytest"
};
`
	scenarios := []Scenario{
		{
			ID:          "s1",
			Executable:  "git",
			FullCommand: "git status",
		},
		{
			ID:          "s2",
			Executable:  "pytest",
			FullCommand: "pytest tests/",
		},
		{
			ID:          "s3",
			Executable:  "curl",
			FullCommand: "curl https://example.com",
		},
	}

	report, err := SimulatePolicySandbox(currentPolicy, draftPolicy, scenarios)
	if err != nil {
		t.Fatalf("unexpected error in simulation: %v", err)
	}

	if report.TotalEvaluated != 3 {
		t.Errorf("expected 3 evaluated, got %d", report.TotalEvaluated)
	}
	if report.CurrentAllowed != 1 {
		t.Errorf("expected 1 current allowed, got %d", report.CurrentAllowed)
	}
	if report.DraftAllowed != 2 {
		t.Errorf("expected 2 draft allowed, got %d", report.DraftAllowed)
	}
	if report.ImpactDiffCount != 1 {
		t.Errorf("expected 1 impact diff, got %d", report.ImpactDiffCount)
	}
	if report.DeniedToAllowed != 1 {
		t.Errorf("expected 1 denied-to-allowed, got %d", report.DeniedToAllowed)
	}

	var foundPytest bool
	for _, item := range report.DiffItems {
		if item.ScenarioID == "s2" {
			foundPytest = true
			if item.CurrentDecision != "DENY" || item.DraftDecision != "ALLOW" {
				t.Errorf("expected pytest to flip from DENY to ALLOW, got curr=%s draft=%s", item.CurrentDecision, item.DraftDecision)
			}
			if item.DiffType != "DENIED_TO_ALLOWED" {
				t.Errorf("expected diff_type DENIED_TO_ALLOWED, got %s", item.DiffType)
			}
		}
	}
	if !foundPytest {
		t.Errorf("pytest diff item not found")
	}
}
