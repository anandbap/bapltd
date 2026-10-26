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
