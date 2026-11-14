package main

import (
	"strings"
	"sync"
	"testing"
)

func setAdminPromptMode(t *testing.T, mode string) {
	t.Helper()
	prevFn := adminPromptCaptureModeFn
	adminPromptCaptureModeFn = func() string { return mode }
	adminPromptModeOnce = sync.Once{}
	t.Cleanup(func() {
		adminPromptCaptureModeFn = prevFn
		adminPromptModeOnce = sync.Once{}
	})
}

// Default: prompts are reported and no local setting can turn that off.
func TestPromptCaptureRequiredIgnoresLocalOptOut(t *testing.T) {
	setAdminPromptMode(t, promptCaptureRequired)
	t.Setenv("BAP_CAPTURE_USER_PROMPT", "false")
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	if !shouldCaptureUserPrompt() {
		t.Fatal("a user environment variable must not disable admin-required prompt reporting")
	}
	got, err := MinimizeTelemetryJSON([]byte(`{"user_prompt":"VISIBLE_PROMPT","prompt_capture_enabled":true,"full_command":"echo PRIVATE_CODE"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "VISIBLE_PROMPT") || strings.Contains(string(got), "PRIVATE_CODE") {
		t.Fatalf("prompt must be kept and the command withheld: %s", got)
	}
}

// The administrator can delegate the choice to users; only then does the local setting count.
func TestPromptCaptureUserControlledHonorsLocalOptOut(t *testing.T) {
	setAdminPromptMode(t, promptCaptureUserControlled)
	t.Setenv("BAP_CAPTURE_USER_PROMPT", "")
	if !shouldCaptureUserPrompt() {
		t.Fatal("user-controlled mode still reports by default")
	}
	t.Setenv("BAP_CAPTURE_USER_PROMPT", "false")
	if shouldCaptureUserPrompt() {
		t.Fatal("user-controlled mode must honor the user's opt-out")
	}
}

// Administrator-off withholds prompt text even if the user asks for it.
func TestPromptCaptureOffCannotBeForcedOnLocally(t *testing.T) {
	setAdminPromptMode(t, promptCaptureOff)
	t.Setenv("BAP_CAPTURE_USER_PROMPT", "true")
	t.Setenv("BAP_TELEMETRY_CONTENT", "redacted")
	if shouldCaptureUserPrompt() {
		t.Fatal("admin-off must not be overridable from the workstation")
	}
	got, err := MinimizeTelemetryJSON([]byte(`{"user_prompt":"HIDDEN_PROMPT","prompt_capture_enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "HIDDEN_PROMPT") || !strings.Contains(string(got), `"prompt_capture_enabled":false`) {
		t.Fatalf("prompt text must be dropped and the flag cleared: %s", got)
	}
}
