package api

import (
	"net/http"
	"testing"

	"bap-controlplane/internal/audit"
)

func TestPromptFallbackAuditAndHookEndpointShareCanonicalTurn(t *testing.T) {
	s := setupTestServer()
	proof := recoveryProof(t, s, "machine")
	if w := resumeRequest(s, proof, `{"session_id":"sess-t","app_id":"codex","instance_id":"machine","client_pid":123}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	headers := map[string]string{"Authorization": "Bearer " + proof}
	w := call(s, http.MethodPost, "/api/v1/audit/ingest", []audit.Event{{EventID: "mcp-fallback", SessionID: "sess-t", Source: "codex", ReportingLayer: "mcp", EvidenceGrade: "self_reported", Executable: "user_prompt", TurnID: "native-turn", UserPrompt: "Review the request", Decision: "observed"}}, headers)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	payload := map[string]any{"session_id": "sess-t", "turn_id": "native-turn", "producer": "codex-lifecycle-hook", "user_prompt": "Fix the parser bug"}
	for i := 0; i < 2; i++ {
		w = call(s, http.MethodPost, "/api/v1/sessions/prompt", payload, headers)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	got, err := s.sessionStore.Get("sess-t")
	if err != nil || got.PromptCount != 1 || got.UserPrompt != "Fix the parser bug" {
		t.Fatalf("duplicate or wrong prompt: %+v %v", got, err)
	}
	s.SetAdminSecurity("test-admin", true)
	text, unlocked := transcriptText(t, s, func(r *http.Request) { r.Header.Set("Authorization", "Bearer test-admin") })
	if !unlocked || text != "Fix the parser bug" {
		t.Fatalf("canonical transcript did not prefer hook: %q", text)
	}
}
