package main

import (
	"os"
	"strings"
)

// headlessStepUpDecision returns the BAP_STEPUP_DECISION value only in test-harness builds
// (`-tags headlessstepup`). The variable is controllable by the agent, so honoring it in a
// shipped build would let an agent approve its own cross-folder write (BAP-1096).
func headlessStepUpDecision() string {
	if !headlessStepUpCompiledIn {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(os.Getenv("BAP_STEPUP_DECISION")))
}
