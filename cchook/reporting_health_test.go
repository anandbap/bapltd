package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCallbackHealthIsMetadataOnlyAndDoesNotImplyApproval(t *testing.T) {
	root := t.TempDir()
	t.Setenv("BAP_STATE_DIR", root)
	payload := HookPayload{HookEventName: "UserPromptSubmit", Source: "claude-code", UserPrompt: "PRIVATE-SYNTHETIC-PROMPT", SessionID: "private-session", ToolInput: ToolInput{Command: "PRIVATE-TOOL-INPUT"}}
	recordNativeCallback(payload)
	body, err := os.ReadFile(filepath.Join(root, "reporting-health", "claude-code-UserPromptSubmit.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"PRIVATE-SYNTHETIC-PROMPT", "private-session", "PRIVATE-TOOL-INPUT", "approved"} {
		if strings.Contains(string(body), private) {
			t.Fatal("private data or inferred approval in health", string(body))
		}
	}
	if !strings.Contains(string(body), `"source":"native_callback"`) {
		t.Fatal(string(body))
	}
	payload.HookEventName = "UnknownHook"
	recordNativeCallback(payload)
	files, _ := os.ReadDir(filepath.Join(root, "reporting-health"))
	if len(files) != 1 {
		t.Fatal("unknown callback fabricated")
	}
}

func TestOnboardingMarkerCorrelatesMetadataWithoutPromptContent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("BAP_STATE_DIR", root)
	id := strings.Repeat("a", 32)
	payload := HookPayload{HookEventName: "UserPromptSubmit", Source: "claude-code", SessionID: "private-native-id", UserPrompt: "BAP-ONBOARDING-" + id + " PRIVATE-REMAINDER"}
	recordNativeCallback(payload)
	body, err := os.ReadFile(filepath.Join(root, "reporting-health", "claude-code-UserPromptSubmit.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), id) || !strings.Contains(string(body), `"session_reference"`) || strings.Contains(string(body), "PRIVATE-REMAINDER") || strings.Contains(string(body), "private-native-id") {
		t.Fatal(string(body))
	}
}
