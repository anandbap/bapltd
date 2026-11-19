package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Hash original JSON, including Write content and Edit replacements which the
// normalized ToolInput struct does not necessarily retain during marshaling.
func nativeInputDigest(raw []byte) string {
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil { return "" }
	var input any
	for _, key := range []string{"tool_input", "toolInput", "input", "args", "arguments", "parameters"} {
		if value, ok := payload[key]; ok { input = value; break }
	}
	canonical, err := json.Marshal(input)
	if err != nil { return "" }
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:])
}

func closeNativeInvocation(payload HookPayload) {
	if payload.ToolUseID == "" { return }
	session := resolveSessionID(payload)
	if session == "" {
		pid, caller := resolveAgentProcess(os.Getppid())
		session = fmt.Sprintf("sess-%s-pid-%d", caller.AppID, pid)
	}
	name := "bapedge"
	if runtime.GOOS == "windows" { name += ".exe" }
	bin := findBinary(name)
	if bin == "" { return }
	cmd := exec.Command(bin, "check", "--source", activeCallerAppID, "--session-id", session,
		"--json", "--tool", payload.ToolName, "--tool-use-id", payload.ToolUseID, "--tool-outcome", "completed")
	cmd.Env = os.Environ()
	// Closing can only remove authority; failure leaves a short-lived decision.
	_ = cmd.Run()
}
