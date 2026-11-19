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
		Overwrite:    map[string]any{"CommandLine": "bapedge.exe exec x"},
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
		if k != "decision" && k != "reason" && k != "overwrite" {
			t.Fatalf("non-proto field %q in Antigravity output: %s", k, data)
		}
	}
	if wire["decision"] == nil {
		t.Fatalf("missing required decision field in Antigravity output: %s", data)
	}
	if wire["systemMessage"] != nil || wire["hookSpecificOutput"] != nil {
		t.Fatalf("forbidden field present in Antigravity wire output: %s", data)
	}

	// Test Antigravity Denial
	denyResp := HookResponse{
		Decision:           "deny",
		PermissionDecision: "deny",
		Reason:             "ZeroStandingPrivilegeViolation",
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: "ZeroStandingPrivilegeViolation",
		},
	}
	denyData, err := json.Marshal(preToolResponseForCaller(denyResp, "antigravity", ""))
	if err != nil {
		t.Fatal(err)
	}
	var denyWire map[string]json.RawMessage
	_ = json.Unmarshal(denyData, &denyWire)
	for k := range denyWire {
		if k != "decision" && k != "reason" && k != "overwrite" {
			t.Fatalf("non-proto field %q in Antigravity denial: %s", k, denyData)
		}
	}
	if denyWire["decision"] == nil || denyWire["reason"] == nil {
		t.Fatalf("missing decision or reason in Antigravity denial: %s", denyData)
	}
}

func TestMultiCallerPreToolResponseCompatibility(t *testing.T) {
	cont := true
	allowed := true
	baseResp := HookResponse{
		Status: "ok", Continue: &cont, Allowed: &allowed, Decision: "approve",
		PermissionDecision: "allow", SystemMessage: "permitted by BAP",
		UpdatedInput: &ToolInput{Command: "bapedge.exe exec test"},
		Overwrite:    map[string]any{"CommandLine": "bapedge.exe exec test"},
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
			AdditionalContext:  "permitted by BAP",
			UpdatedInput:       &ToolInput{Command: "bapedge.exe exec test"},
		},
	}

	// 1. Claude Code
	claudeData, _ := json.Marshal(preToolResponseForCaller(baseResp, "claude-code", ""))
	var claudeMap map[string]any
	_ = json.Unmarshal(claudeData, &claudeMap)
	if claudeMap["systemMessage"] == nil || claudeMap["hookSpecificOutput"] == nil {
		t.Fatalf("Claude Code output missing systemMessage or hookSpecificOutput: %s", claudeData)
	}

	// 2. OpenAI Codex
	codexData, _ := json.Marshal(preToolResponseForCaller(baseResp, "codex", ""))
	var codexMap map[string]any
	_ = json.Unmarshal(codexData, &codexMap)
	if codexMap["hookSpecificOutput"] == nil || codexMap["systemMessage"] != nil {
		t.Fatalf("Codex output invalid: %s", codexData)
	}

	// 3. OpenCode
	opencodeData, _ := json.Marshal(preToolResponseForCaller(baseResp, "opencode", ""))
	var opencodeMap map[string]any
	_ = json.Unmarshal(opencodeData, &opencodeMap)
	if opencodeMap["allowed"] != true || opencodeMap["decision"] != "allow" {
		t.Fatalf("OpenCode output invalid: %s", opencodeData)
	}

	// 4. GitHub Copilot
	copilotData, _ := json.Marshal(preToolResponseForCaller(baseResp, "copilot", ""))
	var copilotMap map[string]any
	_ = json.Unmarshal(copilotData, &copilotMap)
	if copilotMap["allowed"] != true || copilotMap["decision"] != "allow" || copilotMap["hookSpecificOutput"] == nil {
		t.Fatalf("Copilot output invalid: %s", copilotData)
	}

	// 5. Antigravity / Gemini
	agData, _ := json.Marshal(preToolResponseForCaller(baseResp, "antigravity", ""))
	var agMap map[string]any
	_ = json.Unmarshal(agData, &agMap)
	if agMap["decision"] != "allow" || agMap["systemMessage"] != nil || agMap["hookSpecificOutput"] != nil {
		t.Fatalf("Antigravity output invalid: %s", agData)
	}
	if agMap["overwrite"] == nil {
		t.Fatalf("Antigravity output missing overwrite: %s", agData)
	}
}
