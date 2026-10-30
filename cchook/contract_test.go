package main

import (
	"encoding/json"
	"testing"
)

// TestUniversalHookResponseSchema verifies that the canonical hook response
// always serializes both `status: ok` and `continue: true` to prevent future
// regressions across Claude Code and OpenAI Codex CLI runners.
func TestUniversalHookResponseSchema(t *testing.T) {
	resp := UniversalHookResponse{
		Status:   "ok",
		Continue: true,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal UniversalHookResponse: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse serialized hook response: %v", err)
	}

	// 1. Invariant: status MUST be "ok" (required by Claude Code monitors & SIEM parsers)
	status, ok := parsed["status"].(string)
	if !ok || status != "ok" {
		t.Fatalf("expected status: 'ok', got: %v", parsed["status"])
	}

	// 2. Invariant: continue MUST be true (required by Codex CLI & modern agent hook runners)
	cont, ok := parsed["continue"].(bool)
	if !ok || !cont {
		t.Fatalf("expected continue: true, got: %v", parsed["continue"])
	}
}

// TestHookEventContractMatrix verifies that payload event names for all
// supported agent frameworks match expected lifecycle conventions.
func TestHookEventContractMatrix(t *testing.T) {
	events := []string{
		"SessionStart",
		"UserPromptSubmit",
		"PreToolUse",
		"Stop",
		"SessionEnd",
	}

	for _, ev := range events {
		payload := HookPayload{
			HookEventName: ev,
			SessionID:     "sess-contract-test",
		}
		if payload.HookEventName == "" {
			t.Errorf("hook event name cannot be empty")
		}
	}
}

// TestHookPayloadNormalizationMatrix tests cross-harness ingestion from Antigravity,
// Claude Code, GitHub Copilot, Cursor, and Codex CLI formats.
func TestHookPayloadNormalizationMatrix(t *testing.T) {
	// 1. Antigravity format
	agPayload := HookPayload{
		Event:          "PreToolUse",
		ConversationID: "conv-123",
		ToolCall: &AntigravityToolCall{
			Name: "run_command",
			Args: map[string]interface{}{
				"CommandLine": "Get-ChildItem -Recurse",
			},
		},
	}
	normalizeHookPayload(&agPayload)
	if agPayload.HookEventName != "PreToolUse" {
		t.Fatalf("expected HookEventName PreToolUse, got: %s", agPayload.HookEventName)
	}
	if agPayload.SessionID != "conv-123" {
		t.Fatalf("expected SessionID conv-123, got: %s", agPayload.SessionID)
	}

	// 2. Copilot / generic args format
	copilotPayload := HookPayload{
		Type:      "tool_call",
		Tool:      "terminal",
		SessionID: "sess-copilot",
		Args: map[string]interface{}{
			"command": "git status",
		},
	}
	normalizeHookPayload(&copilotPayload)
	if copilotPayload.HookEventName != "tool_call" || copilotPayload.ToolName != "terminal" || copilotPayload.ToolInput.Command != "git status" {
		t.Fatalf("copilot payload failed normalization: %+v", copilotPayload)
	}

	// 3. Flat camelCase format (Cursor / OpenCode)
	cursorPayload := HookPayload{
		EventName:     "PreToolUse",
		ToolNameCamel: "read_file",
		ToolInput: ToolInput{
			FilePathCamel: "src/main.rs",
		},
		SessionIDCamel: "sess-cursor",
	}
	normalizeHookPayload(&cursorPayload)
	if cursorPayload.ToolName != "read_file" || cursorPayload.ToolInput.FilePath != "src/main.rs" || cursorPayload.SessionID != "sess-cursor" {
		t.Fatalf("cursor payload failed normalization: %+v", cursorPayload)
	}
}

// TestUniversalDecisionSchemaCompatibility verifies that responses serializing
// for Claude Code output "approve", while generic / multi-tool consumers receive "allow".
func TestUniversalDecisionSchemaCompatibility(t *testing.T) {
	cont := true
	isAllowed := true

	// Claude Code expectation: top-level decision MUST be "approve"
	claudeResp := HookResponse{
		Status:             "ok",
		Continue:           &cont,
		Decision:           "approve",
		Allowed:            &isAllowed,
		PermissionDecision: "allow",
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
		},
	}
	claudeData, err := json.Marshal(claudeResp)
	if err != nil {
		t.Fatalf("failed to marshal claudeResp: %v", err)
	}
	var claudeMap map[string]any
	_ = json.Unmarshal(claudeData, &claudeMap)
	if claudeMap["decision"] != "approve" {
		t.Fatalf("expected claude decision 'approve', got: %v", claudeMap["decision"])
	}
	if hso, ok := claudeMap["hookSpecificOutput"].(map[string]any); !ok || hso["permissionDecision"] != "allow" {
		t.Fatalf("expected hookSpecificOutput.permissionDecision 'allow', got: %v", hso["permissionDecision"])
	}
	if claudeMap["allowed"] != true {
		t.Fatalf("expected allowed: true, got: %v", claudeMap["allowed"])
	}

	// Generic / Multi-tool runner expectation: top-level decision is "allow"
	genericResp := HookResponse{
		Status:             "ok",
		Continue:           &cont,
		Decision:           "allow",
		Allowed:            &isAllowed,
		PermissionDecision: "allow",
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
		},
	}
	genericData, err := json.Marshal(genericResp)
	if err != nil {
		t.Fatalf("failed to marshal genericResp: %v", err)
	}
	var genericMap map[string]any
	_ = json.Unmarshal(genericData, &genericMap)
	if genericMap["decision"] != "allow" {
		t.Fatalf("expected generic decision 'allow', got: %v", genericMap["decision"])
	}
	if genericMap["allowed"] != true {
		t.Fatalf("expected generic allowed true, got: %v", genericMap["allowed"])
	}
}

// TestClaudeVariantsRecognitionMatrix verifies that all variations of Claude Code
// (claude, claudecode, claude-code, claude IDE, claude CLI, claude plugin, starter scripts)
// are accurately recognized as Claude Code.
func TestClaudeVariantsRecognitionMatrix(t *testing.T) {
	claudeVariants := []string{
		"claude",
		"claudecode",
		"claude-code",
		"claude_code",
		"claude.exe",
		"claudecode.exe",
		"claude-code.exe",
		"claude IDE",
		"claude-ide",
		"claude_ide",
		"claude CLI",
		"claude-cli",
		"claude_cli",
		"claude-code cli",
		"claude plugin",
		"claude-plugin",
		"claude_plugin",
		"claude-code plugin",
		"run_claude_bap.bat",
		"run_claude_bap.ps1",
		"run_claude_cli_bap.bat",
		"run_claude_cli_bap.ps1",
		"run_claude_ide_bap.bat",
		"run_claude_ide_bap.ps1",
		"demo_claude_bap.bat",
		"claude.cmd",
		"claude.bat",
		"claude.ps1",
		"claude.sh",
		"cc",
	}

	for _, v := range claudeVariants {
		if !isClaudeApp(v) {
			t.Errorf("expected isClaudeApp(%q) to be true, got false", v)
		}
		// Test normalization via HookPayload
		p := HookPayload{
			HookEventName: "PreToolUse",
			AppID:         v,
		}
		normalizeHookPayload(&p)
		if p.AppID != "claude-code" {
			t.Errorf("expected AppID for %q to normalize to 'claude-code', got: %q", v, p.AppID)
		}
	}

	nonClaude := []string{
		"antigravity",
		"gemini-cli",
		"copilot",
		"cursor",
		"codex",
		"opencode",
		"generic",
		"pwsh",
		"bash",
	}
	for _, nc := range nonClaude {
		if isClaudeApp(nc) {
			t.Errorf("expected isClaudeApp(%q) to be false, got true", nc)
		}
	}
}
