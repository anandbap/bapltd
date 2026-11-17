//go:build !headlessstepup

package cmd

import (
	"os"
	"strings"
	"testing"
)

// BAP-1096: in every shipped build an agent-supplied environment variable or flag must not be
// able to approve a human step-up.

func TestStepUpEnvVarIsIgnoredInShippedBuilds(t *testing.T) {
	for _, v := range []string{"approve", "once", "allow", "session", "project", "global", "o", "p", "g"} {
		t.Setenv("BAP_STEPUP_DECISION", v)
		if got := headlessStepUpDecision(); got != "" {
			t.Fatalf("BAP_STEPUP_DECISION=%q was honored as %q in a shipped build", v, got)
		}
	}
}

func TestStepUpFlagIsRefusedInShippedBuilds(t *testing.T) {
	t.Setenv("BAP_STEPUP_DECISION", "")
	os.Unsetenv("BAP_STEPUP_DECISION")
	applyStepUpFlag("global")
	if v := strings.TrimSpace(os.Getenv("BAP_STEPUP_DECISION")); v != "" {
		t.Fatalf("--stepup-decision leaked into the environment as %q", v)
	}
}
