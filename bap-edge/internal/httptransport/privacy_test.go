package httptransport

import (
	"encoding/json"
	"strings"
	"testing"
)

func withPromptMode(t *testing.T, allowed bool) {
	t.Helper()
	prev := PromptContentProvider
	PromptContentProvider = func() bool { return allowed }
	t.Cleanup(func() { PromptContentProvider = prev })
}

// Prompt reporting is on by default: with no admin policy, prompt text is kept while other
// content (commands, arguments, reasons) is still withheld.
func TestPromptTextReportedByDefault(t *testing.T) {
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	PromptContentProvider = nil
	got, err := MinimizeTelemetryJSON([]byte(`{"user_prompt":"VISIBLE_PROMPT","prompt_capture_enabled":true,"full_command":"echo PRIVATE_CODE"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "VISIBLE_PROMPT") || strings.Contains(string(got), "PRIVATE_CODE") {
		t.Fatalf("expected prompt kept and command withheld: %s", got)
	}
	if !strings.Contains(string(got), `"prompt_capture_enabled":true`) {
		t.Fatalf("capture flag must not be forced off by default: %s", got)
	}
}

func TestMetadataTelemetryWithholdsContent(t *testing.T) {
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	withPromptMode(t, false) // administrator turned prompt reporting off
	raw := []byte(`[{"event_id":"same-id","session_id":"same-session","full_command":"echo PRIVATE_CODE","arguments":"--token=PRIVATE_TOKEN","user_prompt":"PRIVATE_PROMPT","reason":"PRIVATE_REASON","intent":{"evidence":["PRIVATE_EVIDENCE"],"primary":"BUG_FIX","prompt_captured":true}}]`)
	got, err := MinimizeTelemetryJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "PRIVATE_") {
		t.Fatalf("content leaked: %s", got)
	}
	for _, expected := range []string{"same-id", "same-session", "BUG_FIX", "prompt_hash", "metadata"} {
		if !strings.Contains(string(got), expected) {
			t.Fatalf("metadata missing %s", expected)
		}
	}
	var decoded any
	if json.Unmarshal(got, &decoded) != nil {
		t.Fatal("invalid JSON")
	}
}

func TestRedactedCaptureRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("BAP_TELEMETRY_CONTENT", "redacted")
	got, err := MinimizeTelemetryJSON([]byte(`{"full_command":"git commit -m hello --token=SYNTHETIC_SECRET"}`))
	if err != nil || strings.Contains(string(got), "SYNTHETIC_SECRET") || !strings.Contains(string(got), "git commit") {
		t.Fatalf("redaction: %s %v", got, err)
	}
}
