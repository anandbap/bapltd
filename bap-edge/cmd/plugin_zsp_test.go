package cmd

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"bap-edge/internal/authz"
)

func TestPluginAllowsBrokerWrappedZSPAndCommandsButBlocksTampering(t *testing.T) {
	zspDir := t.TempDir()
	t.Setenv("BAP_ZSP_DIR", zspDir)
	t.Setenv("BAP_ZSP", "enforce")
	t.Setenv("BAP_MODE", "enforce")

	sessID := "sess-plugin-zsp-1"

	// 1. Standalone bapedge zsp authorize must be allowed directly.
	zspCmd := `bapedge zsp authorize --session-id "` + sessID + `" --mission CODE_INSPECTION --goal "git status --short; git log -n 10" --actions "git:status,git:log" --resources workspace://current --max-uses 2`
	if resp := evaluateWithBapedgeTool(sessID, "claude-code", "PowerShell", zspCmd, ""); !resp.Allowed {
		t.Fatalf("expected direct bapedge zsp authorize to be allowed, got reason=%q", resp.Reason)
	}

	// 2. Broker-wrapped bapedge zsp authorize (as rewritten by cchook PreToolUse) must also be allowed,
	// even when --caller-binary contains spaces.
	b64ZSP := base64.StdEncoding.EncodeToString([]byte(zspCmd))
	wrappedZSP := `bapedge exec --shell powershell --source claude-code --session-id ` + sessID + ` --cmd-b64 ` + b64ZSP + ` --caller-binary "C:\Program Files\PowerShell\7\pwsh.exe"`
	if resp := evaluateWithBapedgeTool(sessID, "claude-code", "PowerShell", wrappedZSP, ""); !resp.Allowed {
		t.Fatalf("expected broker-wrapped zsp authorize to be allowed, got reason=%q", resp.Reason)
	}

	// 3. Ungranted git command denies with ZSP suggestion (NOT false tamper) and allows retry.
	respDeny := evaluateWithBapedgeTool(sessID, "claude-code", "PowerShell", "git status --short; git log -n 10", "")
	if respDeny.Allowed {
		t.Fatal("expected ungranted git command to be denied")
	}
	if !strings.Contains(respDeny.Reason, "ZeroStandingPrivilegeViolation") || !strings.Contains(respDeny.Suggestion, "git:status,git:log") {
		t.Fatalf("unexpected ZSP denial: reason=%q suggestion=%q", respDeny.Reason, respDeny.Suggestion)
	}

	// 4. Mint grant, then verify broker-wrapped git command is allowed.
	if _, _, err := authz.SubmitTaskEnvelope(zspDir, sessID, "claude-code", "CODE_INSPECTION", "inspect", "inspect git", []string{"git:status", "git:log"}, []string{"workspace://current"}, "", 2, 0); err != nil {
		t.Fatalf("SubmitTaskEnvelope failed: %v", err)
	}
	b64Git := base64.StdEncoding.EncodeToString([]byte("git status --short; git log -n 10"))
	wrappedGit := `bapedge exec --shell powershell --source claude-code --session-id ` + sessID + ` --cmd-b64 ` + b64Git
	if resp := evaluateWithBapedgeTool(sessID, "claude-code", "PowerShell", wrappedGit, ""); !resp.Allowed {
		t.Fatalf("expected broker-wrapped git command to be allowed after grant, got reason=%q", resp.Reason)
	}

	// 5. Real tampering and forged/chained wrappers must still be blocked.
	for _, blocked := range []struct {
		cmd  string
		path string
		tool string
	}{
		{cmd: `rm -f policy.cedar`, tool: "PowerShell"},
		{cmd: `echo "pwn" > interceptor.exe`, tool: "PowerShell"},
		{cmd: wrappedZSP + ` && whoami`, tool: "PowerShell"},
		{cmd: `bapedge exec --source claude-code --session-id wrong-session --cmd-b64 ` + b64ZSP, tool: "PowerShell"},
		{path: `policy.cedar`, tool: "Write"},
	} {
		if resp := evaluateWithBapedgeTool(sessID, "claude-code", blocked.tool, blocked.cmd, blocked.path); resp.Allowed {
			t.Fatalf("expected tampering/forged command to be blocked: %+v", blocked)
		}
	}

	// 6. Emit decision for ZSP must keep continue=true with actionable suggestion.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	emitPluginDecisionWithSuggestion("claude-code", "PreToolUse", "deny", respDeny.Reason, respDeny.Suggestion, nil)
	_ = w.Close()
	os.Stdout = origStdout
	outBytes, _ := io.ReadAll(r)

	var parsed struct {
		Continue           bool `json:"continue"`
		HookSpecificOutput struct {
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(outBytes, &parsed); err != nil {
		t.Fatalf("invalid JSON emitted by plugin decision: %v (%s)", err, string(outBytes))
	}
	if !parsed.Continue || !strings.Contains(parsed.HookSpecificOutput.AdditionalContext, "git:status,git:log") {
		t.Fatalf("expected continue=true and ZSP suggestion in additionalContext, got: %s", string(outBytes))
	}
}
