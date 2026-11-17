package cmd

import (
	"fmt"
	"os"
	"strings"

	"bap-edge/pkg/version"
)

// headlessStepUpDecision returns the non-interactive step-up decision supplied through the
// BAP_STEPUP_DECISION environment variable, or "" when none may be honored.
//
// Both the variable and the `--stepup-decision` flag are inputs an agent controls on its own
// command line, so honoring them would let an agent approve its own escalation (BAP-1096). They
// are accepted only in binaries compiled with `-tags headlessstepup` (automated test harnesses).
// A real human answers through the terminal prompt, a recorded trust grant, or the control-plane
// approval inbox.
func headlessStepUpDecision() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_STEPUP_DECISION")))
	if raw == "" {
		return ""
	}
	if !version.HeadlessStepUpAllowed() {
		return ""
	}
	return raw
}

// applyStepUpFlag records the `--stepup-decision` flag for later resolution. In builds that do
// not allow headless step-up the flag is refused loudly and has no effect.
func applyStepUpFlag(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if !version.HeadlessStepUpAllowed() {
		fmt.Fprintln(os.Stderr, "[BAP] --stepup-decision ignored: self-approval of step-up is not permitted in this build. A human must approve (terminal prompt, `bapedge trust`, or the approval inbox).")
		return
	}
	_ = os.Setenv("BAP_STEPUP_DECISION", value)
}
