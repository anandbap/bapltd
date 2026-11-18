package main

import (
	"encoding/json"
	"testing"
)

func TestAntigravityPreToolResponseOnlyProtoFields(t *testing.T) {
	cont := true
	allowed := true
	resp := HookResponse{
		Status: "ok", Continue: &cont, Allowed: &allowed, Decision: "allow",
		PermissionDecision: "allow", SystemMessage: "authorized",
		UpdatedInput: &ToolInput{Command: "bapedge.exe exec x"},
		Overwrite:    map[string]any{"command": "x"},
		HookSpecificOutput: HookSpecificOutput{
			HookEventName: "PreToolUse", PermissionDecision: "allow", AdditionalContext: "authorized",
		},
	}
	data, err := json.Marshal(preToolResponseForCaller(resp, "antigravity", ""))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	_ = json.Unmarshal(data, &wire)
	for k := range wire {
		if k != "decision" && k != "systemMessage" && k != "hookSpecificOutput" {
			t.Fatalf("non-proto field %q in Antigravity output: %s", k, data)
		}
	}
	if wire["decision"] == nil || wire["hookSpecificOutput"] == nil {
		t.Fatalf("missing required fields: %s", data)
	}
}
