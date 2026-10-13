package main

import (
	"encoding/json"
	"testing"
)

func TestCopilotExecResponseUnmarshal(t *testing.T) {
	jsonPayload := `{
		"allowed": false,
		"reason": "Denial triggered by: policy policy1",
		"suggestion": "Access to .env is forbidden",
		"warning": "Security alert"
	}`

	var resp ExecResponse
	if err := json.Unmarshal([]byte(jsonPayload), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if resp.Allowed {
		t.Errorf("expected allowed=false, got true")
	}
	if resp.Reason != "Denial triggered by: policy policy1" {
		t.Errorf("unexpected reason: %q", resp.Reason)
	}
	if resp.Suggestion != "Access to .env is forbidden" {
		t.Errorf("unexpected suggestion: %q", resp.Suggestion)
	}
}

func TestFindBinaryDefaultFallback(t *testing.T) {
	bin := findBinary("nonexistent-test-binary-xyz")
	if bin != "nonexistent-test-binary-xyz" {
		t.Errorf("expected fallback to binary name, got %q", bin)
	}
}
