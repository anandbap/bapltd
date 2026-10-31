package main

import (
	"encoding/json"
	"testing"
)

func TestCodexPreToolResponseUsesNativeEnvelope(t *testing.T) {
	for _, decision := range []string{"allow", "deny"} {
		cont := decision == "allow"
		resp := HookResponse{Continue: &cont, StopReason: "legacy denial", Decision: decision, Status: "ok", HookSpecificOutput: HookSpecificOutput{HookEventName: "PreToolUse", PermissionDecision: decision, PermissionDecisionReason: "Cedar result", UpdatedInput: &ToolInput{Command: "bapedge exec approved-command", Cmd: "legacy alias", CommandLine: "legacy alias"}}}
		data, err := json.Marshal(preToolResponseForCaller(resp, "codex", ""))
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		_ = json.Unmarshal(data, &wire)
		if len(wire) != 1 || wire["hookSpecificOutput"] == nil {
			t.Fatalf("unsupported Codex envelope: %s", data)
		}
		var specific HookSpecificOutput
		_ = json.Unmarshal(wire["hookSpecificOutput"], &specific)
		if specific.PermissionDecision != decision || specific.UpdatedInput.Command == "" {
			t.Fatalf("decision or broker rewrite lost: %s", data)
		}
		if specific.UpdatedInput.Cmd != "" || specific.UpdatedInput.CommandLine != "" {
			t.Fatalf("legacy tool arguments escaped into Codex input: %s", data)
		}
		legacy, _ := json.Marshal(preToolResponseForCaller(resp, "claude-code", ""))
		_ = json.Unmarshal(legacy, &wire)
		if wire["continue"] == nil {
			t.Fatal("Claude legacy contract changed")
		}
	}
}
