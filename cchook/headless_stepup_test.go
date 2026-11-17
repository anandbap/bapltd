//go:build !headlessstepup

package main

import "testing"

func TestInterceptorIgnoresStepUpEnvInShippedBuilds(t *testing.T) {
	for _, v := range []string{"approve", "once", "allow", "session", "project", "global"} {
		t.Setenv("BAP_STEPUP_DECISION", v)
		if got := headlessStepUpDecision(); got != "" {
			t.Fatalf("BAP_STEPUP_DECISION=%q was honored as %q by a shipped interceptor", v, got)
		}
	}
}
