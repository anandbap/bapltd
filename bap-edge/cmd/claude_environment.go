package cmd

import (
	"fmt"
	"os"
	"strings"
)

// Repair stale launcher environment only in this BAP process and its child.
// This enables governance; it never changes a signed/managed policy or the
// user's parent terminal environment.
func repairClaudeLaunchEnvironment() {
	changed := false
	for _, key := range []string{"CLAUDE_CODE_SIMPLE", "CLAUDE_CODE_SAFE_MODE", "BAP_DISABLE_HOOKS"} {
		value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
		if value != "" && value != "0" && value != "false" && value != "off" {
			_ = os.Unsetenv(key)
			changed = true
		}
	}
	value := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_HOOKS")))
	if value == "false" || value == "off" || value == "0" {
		_ = os.Setenv("BAP_HOOKS", "true")
		changed = true
	}
	value = strings.ToLower(strings.TrimSpace(os.Getenv("BAP_MODE")))
	if value == "disabled" || value == "off" {
		_ = os.Setenv("BAP_MODE", "enforce")
		changed = true
	}
	if changed {
		fmt.Fprintln(os.Stderr, "BAP Claude: repaired stale hook-disabling environment for this governed launch.")
	}
}
