package api

import (
	"testing"

	"bap-controlplane/internal/policy"
)

func ingestPrivacyProbe(t *testing.T, s *Server, id string) {
	t.Helper()
	const collector = "synthetic-collector-credential-32-characters"
	w := call(s, "POST", "/api/v1/audit/ingest", []map[string]any{{"event_id": id, "source": "collector", "full_command": "PRIVATE_CODE", "user_prompt": "PROMPT_TEXT", "reason": "PRIVATE_REASON", "decision": "deny"}}, map[string]string{"Authorization": "Bearer " + collector})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func newPrivacyServer(t *testing.T) *Server {
	t.Helper()
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	s := setupTestServer()
	s.SetEnvironmentMode("prod")
	if err := s.SetTelemetrySecurity("synthetic-collector-credential-32-characters"); err != nil {
		t.Fatal(err)
	}
	return s
}

// Prompt reporting is on by default (administrator-owned, "required"): prompt text is retained
// while commands and reasons stay withheld by the generic metadata setting.
func TestProductionIngressReportsPromptsByDefaultButWithholdsCommands(t *testing.T) {
	s := newPrivacyServer(t)
	if got := s.policyStore.PromptCaptureMode(); got != policy.PromptCaptureRequired {
		t.Fatalf("default prompt capture mode = %q, want required", got)
	}
	ingestPrivacyProbe(t, s, "metadata-default")
	events := s.auditStore.List(0)
	if len(events) != 1 || events[0].UserPrompt != "PROMPT_TEXT" || events[0].FullCommand != "" || events[0].Reason == "PRIVATE_REASON" {
		t.Fatalf("unexpected retention under default prompt capture: %+v", events)
	}
	if valid, err := s.auditStore.VerifyChain(); !valid {
		t.Fatal(err)
	}
}

// When the administrator turns prompt reporting off, prompt text is not retained.
func TestProductionIngressWithholdsPromptsWhenAdminTurnsCaptureOff(t *testing.T) {
	s := newPrivacyServer(t)
	if _, err := s.policyStore.SetPromptCapture(policy.PromptCaptureOff); err != nil {
		t.Fatal(err)
	}
	ingestPrivacyProbe(t, s, "metadata-off")
	events := s.auditStore.List(0)
	if len(events) != 1 || events[0].UserPrompt != "" || events[0].FullCommand != "" {
		t.Fatalf("prompt retained while capture is off: %+v", events)
	}
}

// The mode is signed: changing it must change the canonical payload, and the default must not,
// so unchanged fleets keep verifying with older clients.
func TestPromptCaptureIsInSignedPayloadOnlyWhenChanged(t *testing.T) {
	base := policy.Bundle{Version: 3, Digest: "d", UpdatedAt: "u"}
	plain := string(policy.CanonicalBundlePayload(base, "asset"))
	user := base
	user.PromptCapture = policy.PromptCaptureUserControlled
	if string(policy.CanonicalBundlePayload(user, "asset")) == plain {
		t.Fatal("prompt_capture is not covered by the signature")
	}
	if got := policy.NormalizePromptCapture("required"); got != "" {
		t.Fatalf("default must normalise to empty so existing signatures are unchanged, got %q", got)
	}
}
