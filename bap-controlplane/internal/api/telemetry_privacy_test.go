package api

import (
	"testing"
)

func TestProductionMetadataIngressDoesNotRetainContent(t *testing.T) {
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	s := setupTestServer()
	s.SetEnvironmentMode("prod")
	const collector = "synthetic-collector-credential-32-characters"
	if err := s.SetTelemetrySecurity(collector); err != nil {
		t.Fatal(err)
	}
	w := call(s, "POST", "/api/v1/audit/ingest", []map[string]any{{"event_id": "metadata-collector", "source": "collector", "full_command": "PRIVATE_CODE", "user_prompt": "PRIVATE_PROMPT", "reason": "PRIVATE_REASON", "decision": "deny"}}, map[string]string{"Authorization": "Bearer " + collector})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	events := s.auditStore.List(0)
	if len(events) != 1 || events[0].FullCommand != "" || events[0].UserPrompt != "" || events[0].Reason == "PRIVATE_REASON" {
		t.Fatalf("private content retained: %+v", events)
	}
	if valid, err := s.auditStore.VerifyChain(); !valid {
		t.Fatal(err)
	}
}
