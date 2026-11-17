//go:build headlessstepup

package cmd

import "testing"

// Test-harness builds (-tags headlessstepup) keep the non-interactive decision for automated suites.
func TestStepUpEnvVarHonoredOnlyInTaggedHarnessBuild(t *testing.T) {
	t.Setenv("BAP_STEPUP_DECISION", "Approve")
	if got := headlessStepUpDecision(); got != "approve" {
		t.Fatalf("tagged harness build should honor the decision, got %q", got)
	}
}
