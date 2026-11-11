package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

	// 7. Leading PowerShell call operator `& "C:\Program Files\BAP\bapedge.exe"` must also unwrap cleanly.
	psZSP := `& "C:\Program Files\BAP\bapedge.exe" zsp authorize --session-id "` + sessID + `" --mission CODE_INSPECTION --goal "git status" --actions "git:status" --resources workspace://current`
	if resp := evaluateWithBapedgeTool(sessID, "claude-code", "PowerShell", psZSP, ""); !resp.Allowed {
		t.Fatalf("expected PowerShell call-operator ZSP command to be allowed, got reason=%q", resp.Reason)
	}
	psWrappedGit := `& "C:\Program Files\BAP\bapedge.exe" exec --shell powershell --source claude-code --session-id ` + sessID + ` --cmd-b64 ` + b64Git
	if resp := evaluateWithBapedgeTool(sessID, "claude-code", "PowerShell", psWrappedGit, ""); !resp.Allowed {
		t.Fatalf("expected PowerShell call-operator broker-wrapped git command to be allowed, got reason=%q", resp.Reason)
	}
}

func TestSyncBinaryAndStandaloneHookDetection(t *testing.T) {
	tmp := t.TempDir()
	fresh := filepath.Join(tmp, "bapedge.exe")
	stale := filepath.Join(tmp, "plugins", "claude", "scripts", "bap-hook-adapter.exe")
	if err := os.MkdirAll(filepath.Dir(stale), 0755); err != nil {
		t.Fatal(err)
	}
	wantBytes := []byte("MZ-NEW-BAPEDGE-BYTES")
	if err := os.WriteFile(fresh, wantBytes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("MZ-OLD-STALE-BYTES"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := syncBinaryIfChanged(fresh, stale); err != nil {
		t.Fatalf("syncBinaryIfChanged failed: %v", err)
	}
	got, err := os.ReadFile(stale)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantBytes) {
		t.Fatalf("expected stale adapter binary to be overwritten with fresh bytes, got %q", string(got))
	}

	if runtime.GOOS == "windows" {
		ws := filepath.Join(tmp, "ws")
		if hasStandaloneClaudeBAPHook(ws) {
			// Skip assertion if real host ~/.claude/settings.json configures BAP hook
			_ = ws
		}
		claudeDir := filepath.Join(ws, ".claude")
		_ = os.MkdirAll(claudeDir, 0755)
		_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"interceptor.exe"}]}]}}`), 0644)
		if !hasStandaloneClaudeBAPHook(ws) {
			t.Fatal("expected hasStandaloneClaudeBAPHook to detect workspace .claude/settings.json interceptor hook")
		}
	}
}

func TestRunZSPValidationDefaultMaxUsesAndAncestorPIDSession(t *testing.T) {
	zspDir := t.TempDir()
	t.Setenv("BAP_ZSP_DIR", zspDir)

	// 1. Space-separated action must fail fast with canonical colon syntax hint.
	err := RunZSP([]string{
		"authorize",
		"--session-id", "sess-bad-zsp",
		"--mission", "CODE_INSPECTION",
		"--goal", "inspect git",
		"--actions", "git status,git log",
		"--resources", "workspace://current",
	})
	if err == nil || !strings.Contains(err.Error(), "git:status") {
		t.Fatalf("expected RunZSP authorize to reject \"git status\" and suggest \"git:status\", got: %v", err)
	}

	// 2. Omitting --max-uses with 3 canonical actions defaults MaxUses to 3 for parallel execution.
	if err := RunZSP([]string{
		"authorize",
		"--session-id", "sess-multi-zsp",
		"--mission", "CODE_INSPECTION",
		"--goal", "inspect git status, log, branch",
		"--actions", "git:status,git:log,git:branch",
		"--resources", "workspace://current",
	}); err != nil {
		t.Fatalf("RunZSP authorize multi-action failed: %v", err)
	}
	rep, err := authz.ListSessionZSPStatus(zspDir, "sess-multi-zsp", "claude-code")
	if err != nil {
		t.Fatalf("ListSessionZSPStatus failed: %v", err)
	}
	if len(rep.ActiveGrants) != 1 || rep.ActiveGrants[0].MaxUses != 3 || rep.ActiveGrants[0].RemainingUses != 3 {
		t.Fatalf("expected multi-action authorize without --max-uses to mint MaxUses=3, got: %+v", rep.ActiveGrants)
	}

	// 3. Ancestor PID walk resolves the agent session ID across subshell boundaries.
	tmpWS := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpWS); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	markerDir := filepath.Join(tmpWS, ".bap", "sessions")
	if err := os.MkdirAll(markerDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markerDir, "pid-9001.json"), []byte(`{"session_id":"sess-ancestor-9001"}`), 0644); err != nil {
		t.Fatal(err)
	}

	processes := []agentProcess{
		{PID: 9001, ParentPID: 100},
		{PID: 9002, ParentPID: 9001},
		{PID: 9003, ParentPID: 9002},
	}
	pids := collectAncestorPIDs(9003, processes)
	if got := resolveSessionIDFromPIDMarkers(pids...); got != "sess-ancestor-9001" {
		t.Fatalf("expected ancestor PID marker to resolve \"sess-ancestor-9001\", got %q (pids=%v)", got, pids)
	}
}
