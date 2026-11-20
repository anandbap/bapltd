package cmd

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/pkg/types"
)

func (ec *execContext) observeDefense(layer int, producer, decision, reason string) {
	if ec.actionID == "" {
		ec.actionID = os.Getenv("BAP_OP_ID")
		if ec.actionID == "" {
			ec.actionID = audit.GenerateEventID()
		}
	}
	if reason == "" {
		switch producer {
		case "edge/content-pinning":
			reason = "SHA-256 verifier matched the configured asset pin"
		case "edge/execution-broker":
			reason = "Broker completed the reported policy and execution decision"
		}
	}
	active, _ := configuredDevOverride()
	o := types.DefenseObservation{EventID: fmt.Sprintf("%s/layer-%d/%d", ec.actionID, layer, len(ec.defenseObservations)), ActionID: ec.actionID, Layer: layer, Producer: producer, Decision: decision, Reason: reason, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Scope: "action", Diagnostic: isShowcaseDiagnosticContext(), OverrideActive: active}
	ec.defenseObservations = append(ec.defenseObservations, o)
}

func recordNativeDefenseDecision(session, client, invocation, decision, reason string) {
	if isShowcaseDiagnosticContext() {
		return
	}
	action := invocation
	if action == "" {
		action = audit.GenerateEventID()
	}
	digest := sha256.Sum256([]byte(session + "\x00" + client + "\x00" + action + "\x00" + decision))
	id := fmt.Sprintf("hook-%x", digest[:16])
	active, _ := configuredDevOverride()
	o := types.DefenseObservation{EventID: id, ActionID: action, Layer: 1, Producer: "native-hook/" + normalizeClientAppID(client), Decision: decision, Reason: reason, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Scope: "action", OverrideActive: active}
	entry := audit.AuditEntry{EventID: id, SessionID: session, Source: normalizeClientAppID(client), ReportingLayer: "hook", Executable: "defense_hook", Decision: "observed", Timestamp: time.Now().UTC(), DefenseObservations: []types.DefenseObservation{o}}
	if err := audit.Log(&entry, audit.DefaultLogPath()); err != nil {
		fmt.Fprintln(os.Stderr, "BAP hook evidence retained-state error:", err)
	}
}

func pinDecision(valid bool) string {
	if valid {
		return "passed"
	}
	return "mismatch"
}
