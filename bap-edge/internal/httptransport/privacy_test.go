package httptransport

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMetadataTelemetryWithholdsContent(t *testing.T) {
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
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
