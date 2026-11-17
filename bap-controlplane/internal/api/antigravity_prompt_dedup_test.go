package api

import (
	"net/http"
	"testing"
)

// Antigravity hooks report the raw <USER_REQUEST>-wrapped payload while the transcript
// tailer reports the extracted text. Both must collapse into a single prompt.
func TestAntigravityWrappedAndExtractedPromptsCountOnce(t *testing.T) {
	s := setupTestServer()
	proof := recoveryProof(t, s, "machine")
	if w := resumeRequest(s, proof, `{"session_id":"sess-agy","app_id":"antigravity","instance_id":"machine","client_pid":123}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	headers := map[string]string{"Authorization": "Bearer " + proof}

	wrapped := "<USER_REQUEST>\nFix the parser bug\n</USER_REQUEST>\n<ADDITIONAL_METADATA>cwd=/x</ADDITIONAL_METADATA>"
	reports := []map[string]any{
		{"session_id": "sess-agy", "producer": "native-plugin-hook", "user_prompt": wrapped},
		{"session_id": "sess-agy", "producer": "antigravity-cli", "user_prompt": "Fix the parser bug"},
	}
	for _, r := range reports {
		if w := call(s, http.MethodPost, "/api/v1/sessions/prompt", r, headers); w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	got, err := s.sessionStore.Get("sess-agy")
	if err != nil || got.PromptCount != 1 {
		t.Fatalf("expected one prompt across layers, got %+v %v", got, err)
	}
}
