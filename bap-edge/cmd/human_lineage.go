package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bap-edge/internal/authz"
	"bap-edge/internal/state"
)

// Human-only actions (approve, deny, auto-approve ON, the approval inbox) used to be guarded by one
// environment marker, BAP_IN_BROKER, which any process that launches bapedge directly can simply not set.
//
// This adds a second, environment-independent check: process LINEAGE. If this process descends from a
// process that BAP itself registered as an agent session (a pid-<pid>.json marker whose recorded process
// birth still matches the live process), a human-only action is refused, because a PTY or helper the
// agent spawned is still inside the agent's process tree no matter what environment it was given.
//
// Design rules, chosen so BAP cannot lock a developer out:
//   - Positive evidence only. No marker, no process list, a missing birth stamp or a mismatching
//     birth (PID reuse) all mean "not an agent", so a developer's own terminal is never refused.
//   - It adds to, and never replaces, the BAP_IN_BROKER check and the interactive one-time challenge.
//   - It does not claim to stop an agent that escapes its own process tree (for example by asking the
//     OS to start a process under another parent). That remains ZSP-REVIEW-01: an authenticated
//     approval channel outside the agent's security context.

// agentLineageProbe is replaceable in tests.
var agentLineageProbe = detectAgentLineage

type agentSessionMarker struct {
	SessionID string `json:"session_id"`
	PID       int    `json:"pid"`
	Birth     string `json:"process_birth"`
}

// liveAgentMarker returns the session recorded for pid when BAP registered that exact live process.
func liveAgentMarker(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	dirs := []string{state.SessionsDir(), filepath.Join(".bap", "sessions")}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("pid-%d.json", pid)))
		if err != nil {
			continue
		}
		var m agentSessionMarker
		if json.Unmarshal(data, &m) != nil || m.SessionID == "" || m.PID != pid || m.Birth == "" {
			continue
		}
		if processBirth(pid) != m.Birth {
			continue
		}
		return m.SessionID, true
	}
	return "", false
}

// detectAgentLineage reports whether this process descends from a registered, live agent session.
func detectAgentLineage() (string, bool) {
	processes, err := listAgentProcesses()
	if err != nil {
		return "", false // fail open: never lock the developer out because the process table was unreadable
	}
	for _, pid := range collectAncestorPIDs(os.Getppid(), processes) {
		if sid, ok := liveAgentMarker(pid); ok {
			return sid, true
		}
	}
	return "", false
}

// refuseAgentContext returns a non-nil error when a human-only action is being attempted from inside an
// agent: either the broker marker is present or the process descends from a registered agent session.
// what completes the sentence "... cannot run ...".
func refuseAgentContext(what string) error {
	if strings.TrimSpace(os.Getenv("BAP_IN_BROKER")) != "" {
		return fmt.Errorf("%w: %s", authz.ErrHighRiskApprovalRequired, what)
	}
	if sid, ok := agentLineageProbe(); ok {
		return fmt.Errorf("%w: %s (this process descends from agent session %q; open a terminal that is not started by the agent)", authz.ErrHighRiskApprovalRequired, what, sid)
	}
	return nil
}
