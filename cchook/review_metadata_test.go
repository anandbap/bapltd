package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReviewMetadataRetainsOperationCorrelation(t *testing.T) {
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	raw, err := MinimizeTelemetryJSON([]byte(`{"full_command":"Glob private-pattern","reason":"private reason","executable":"Glob"}`))
	if err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	if err := json.Unmarshal(raw, &first); err != nil {
		t.Fatal(err)
	}
	if first["content_hash"] == nil || first["full_command"] != nil || strings.Contains(string(raw), "private") {
		t.Fatalf("metadata must correlate operations without content: %s", raw)
	}
	retry, err := MinimizeTelemetryJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	var second map[string]any
	_ = json.Unmarshal(retry, &second)
	if first["content_hash"] != second["content_hash"] {
		t.Fatal("retry changed correlation hash")
	}
}

func TestLocalCaptureIndependentOfTelemetryAndUntruncated(t *testing.T) {
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	command := "echo " + strings.Repeat("local-content-", 500)
	raw, _ := json.Marshal(map[string]any{"full_command": command, "reason": "specific local reason", "arguments": "--token=TEST_SECRET", "action": command, "deviation_reason": "specific local reason"})
	local, err := CaptureLocalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	var captured map[string]any
	_ = json.Unmarshal(local, &captured)
	if captured["full_command"] != command || captured["reason"] != "specific local reason" || strings.Contains(string(local), "TEST_SECRET") {
		t.Fatal("local evidence missing or secret unredacted")
	}
	outbound, err := MinimizeTelemetryJSON(local)
	if err != nil || strings.Contains(string(outbound), "local-content") || strings.Contains(string(outbound), "specific local reason") {
		t.Fatalf("sync leaked local content: %s %v", outbound, err)
	}
}

func TestReviewSearchInputAndDecisionCategory(t *testing.T) {
	previous := fileHookEvidence
	defer func() { fileHookEvidence = previous }()
	var payload HookPayload
	if err := json.Unmarshal([]byte(`{"tool_name":"mcp__update_plan","tool_input":{"plan":[{"step":"inspect source","status":"in_progress"}]}}`), &payload); err != nil {
		t.Fatal(err)
	}
	prepareHookEvidence(payload, "", "test")
	if !strings.Contains(fileHookEvidence.InputDetails, "inspect source") {
		t.Fatal("unknown MCP tool input lost")
	}
	prepareHookEvidence(HookPayload{ToolName: "Glob", ToolInput: ToolInput{Pattern: "**/*.go"}}, "", "test")
	if !strings.Contains(fileHookEvidence.InputDetails, "**/*.go") {
		t.Fatal("search pattern lost")
	}
	prepareHookEvidence(HookPayload{ToolName: "Read"}, "", "test")
	if fileHookEvidence.InputDetails != "{}" {
		t.Fatal("previous search input leaked")
	}
	if hookDecisionConcept("ZeroStandingPrivilegeViolation: private details") != "ZSP_DENY_NO_GRANT" {
		t.Fatal("category lost")
	}
	if hookDecisionConcept("unknown private reason") != "" {
		t.Fatal("unknown reason exposed")
	}
}
