package main

import (
	"strings"
	"testing"
)

func TestBrokerShellToolMatrix(t *testing.T) {
	for _, tool := range []string{"Bash", "sh", "zsh", "PowerShell", "pwsh", "cmd"} {
		want := strings.ToLower(tool)
		if got := brokerShellForTool(tool); got != want || brokerShellFlag(tool) != " --shell "+want {
			t.Fatalf("%s shell not preserved: %q", tool, got)
		}
	}
	if brokerShellForTool("terminal") != "auto" || brokerShellFlag("Read") != "" {
		t.Fatal("unknown tool invented a shell")
	}
}

func TestSessionStartAndPromptDeliverConsistentZSPContext(t *testing.T) {
	for _, auto := range []string{"0", "1"} {
		t.Setenv("BAP_ZSP_AUTO_GRANTS", auto)
		start := claudeZSPHookResponse("SessionStart", "fresh-session")
		prompt := claudeZSPHookResponse("UserPromptSubmit", "fresh-session")
		if start.HookSpecificOutput.HookEventName != "SessionStart" || prompt.HookSpecificOutput.HookEventName != "UserPromptSubmit" {
			t.Fatal("context has incorrect native event")
		}
		ctx := start.HookSpecificOutput.AdditionalContext
		if ctx != prompt.HookSpecificOutput.AdditionalContext || !strings.Contains(ctx, "fresh-session") {
			t.Fatal("startup and prompt context differ")
		}
		if strings.Contains(ctx, "Submit routine command batches normally") != (auto == "1") {
			t.Fatal("instructions contradict effective auto-grant mode")
		}
	}
}
