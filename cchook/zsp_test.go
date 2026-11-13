package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestIsCedarInvariantViolationCoversZSPAndRootEscape(t *testing.T) {
	cases := []struct {
		reason string
		want   bool
	}{
		{"Explicit deny or default deny (no permit policy matched)", false},
		{"ZeroStandingPrivilegeViolation: agent principal has ZERO standing privileges", true},
		{"Security Invariant Violation: Filesystem root path escapes workspace boundary", true},
		{"task grant already burned (max uses exceeded)", true},
		{"attempted action exceeds granted task scope", true},
	}
	for _, tc := range cases {
		if got := isCedarInvariantViolation(tc.reason); got != tc.want {
			t.Errorf("isCedarInvariantViolation(%q) = %v, want %v", tc.reason, got, tc.want)
		}
	}
}

func setupZSPHookTestEnv(t *testing.T) (repoRoot, bapOut, interOut string) {
	t.Helper()
	var err error
	repoRoot, err = filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	tmpBin, err := os.MkdirTemp("", "bap-cchook-zsp-*")
	if err != nil {
		t.Fatalf("failed to create temp bin dir: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 6; i++ {
			if os.RemoveAll(tmpBin) == nil {
				return
			}
			time.Sleep(150 * time.Millisecond)
		}
	})

	bapOut = filepath.Join(tmpBin, "bapedge.exe")
	buildCmd := exec.Command("go", "build", "-C", filepath.Join(repoRoot, "bap-edge"), "-o", bapOut, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build bapedge.exe for test: %v\n%s", err, string(out))
	}

	interOut = filepath.Join(tmpBin, "interceptor.exe")
	buildInter := exec.Command("go", "build", "-o", interOut, ".")
	if out, err := buildInter.CombinedOutput(); err != nil {
		t.Fatalf("failed to build interceptor.exe for test: %v\n%s", err, string(out))
	}

	zspDir := t.TempDir()
	stateDir := t.TempDir()
	pepHome := t.TempDir()
	t.Setenv("BAP_ZSP_DIR", zspDir)
	t.Setenv("BAP_ZSP", "enforce")
	t.Setenv("BAP_ZSP_ENABLED", "1")
	t.Setenv("BAP_NON_INTERACTIVE", "1")
	t.Setenv("BAP_EDGE_BIN", bapOut)
	t.Setenv("LTD_STATE_DIR", stateDir)
	t.Setenv("BAP_PEP_HOME", pepHome)
	t.Setenv("LTD_ENFORCE_MODE", "enforce")
	t.Setenv("BAP_MODE", "enforce")
	t.Setenv("LTD_SOURCE", "claude-code")
	t.Setenv("BAP_SESSION_ID", "")
	t.Setenv("CLAUDE_SESSION_ID", "")
	t.Setenv("PATH", tmpBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return repoRoot, bapOut, interOut
}

func TestInterceptorDevOverrideOmitsGrantGuidance(t *testing.T) {
	_, _, interceptor := setupZSPHookTestEnv(t)
	workspace := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("BAP_ENVIRONMENT", "development")
	t.Setenv("BAP_DEV_OVERRIDE", "")
	t.Setenv("BAP_DEV_MODE", "")
	t.Setenv("BAP_CISO_TOKEN", "")
	t.Setenv("BAP_ADMIN_TOKEN", "")
	t.Setenv("BAP_WORKSPACE_ROOT", workspace)
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	t.Setenv("BAP_SERVER_URL", "http://127.0.0.1:1")
	// This test verifies prompt/tool decisions, not background watcher startup.
	liveness := watcherLivenessPath("sess-dev-no-grants")
	if err := os.MkdirAll(filepath.Dir(liveness), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(liveness, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	marker, _ := json.Marshal(map[string]any{"active": true, "expires_at": time.Now().Add(time.Hour)})
	if err := os.WriteFile(filepath.Join(os.Getenv("BAP_STATE_DIR"), "dev-override.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []map[string]any{
		{"hook_event_name": "UserPromptSubmit", "app_id": "claude-code", "session_id": "sess-dev-no-grants", "user_prompt": "Read the README"},
		{"hook_event_name": "PreToolUse", "app_id": "claude-code", "session_id": "sess-dev-no-grants", "tool_name": "Read", "tool_input": map[string]any{"file_path": filepath.Join(workspace, "README.md")}},
	} {
		body, _ := json.Marshal(payload)
		cmd := exec.Command(interceptor)
		cmd.Dir = workspace
		cmd.Stdin = bytes.NewReader(body)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("hook: %v output=%s stderr=%s", err, out, stderr.String())
		}
		for _, forbidden := range []string{"bapedge zsp authorize", "ZeroStandingPrivilegeViolation", `"permissionDecision":"deny"`, `"permissionDecision": "deny"`} {
			if strings.Contains(string(out), forbidden) {
				t.Fatalf("override must not request a grant or deny the fixture: %s", out)
			}
		}
		if !json.Valid(out) {
			t.Fatalf("invalid hook response: %s", out)
		}
	}
}

func TestInterceptorPreToolUseBlocksScenario1WithBuiltBroker(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows binary verification test")
	}
	_, _, interOut := setupZSPHookTestEnv(t)

	// 1. Test PowerShell whoami without any TaskGrant -> MUST DENY with ZeroStandingPrivilegeViolation
	pWho, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "PowerShell",
		"session_id":      "sess-cchook-sc1",
		"tool_input":      map[string]any{"command": "whoami"},
	})
	cmd1 := exec.Command(interOut)
	cmd1.Stdin = bytes.NewReader(pWho)
	out1, err := cmd1.CombinedOutput()
	if err != nil {
		t.Fatalf("interceptor failed on whoami: %v\n%s", err, string(out1))
	}
	if !strings.Contains(string(out1), `"permissionDecision":"deny"`) && !strings.Contains(string(out1), `"permissionDecision": "deny"`) {
		t.Fatalf("expected deny for ungranted whoami, got: %s", string(out1))
	}
	if !strings.Contains(string(out1), "ZeroStandingPrivilegeViolation") {
		t.Fatalf("expected ZeroStandingPrivilegeViolation in output, got: %s", string(out1))
	}

	// 2. Test PowerShell Get-ChildItem -Force \ -> MUST DENY (filesystem root escape)
	pRoot, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "PowerShell",
		"session_id":      "sess-cchook-sc1",
		"tool_input":      map[string]any{"command": `Get-ChildItem -Force \`},
	})
	cmd2 := exec.Command(interOut)
	cmd2.Stdin = bytes.NewReader(pRoot)
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("interceptor failed on root listing: %v\n%s", err, string(out2))
	}
	if !strings.Contains(string(out2), `"permissionDecision":"deny"`) && !strings.Contains(string(out2), `"permissionDecision": "deny"`) {
		t.Fatalf("expected deny for root listing, got: %s", string(out2))
	}

	// 3. Test native LS tool without TaskGrant -> MUST DENY
	pLS, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "LS",
		"session_id":      "sess-cchook-sc1",
		"tool_input":      map[string]any{"path": `\`},
	})
	cmd3 := exec.Command(interOut)
	cmd3.Stdin = bytes.NewReader(pLS)
	out3, err := cmd3.CombinedOutput()
	if err != nil {
		t.Fatalf("interceptor failed on LS: %v\n%s", err, string(out3))
	}
	if !strings.Contains(string(out3), `"permissionDecision":"deny"`) && !strings.Contains(string(out3), `"permissionDecision": "deny"`) {
		t.Fatalf("expected deny for ungranted native LS(/), got: %s", string(out3))
	}
}

func TestInterceptorPreToolUseScenario2ZSPAuthorizeAndGitStatus(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows binary verification test")
	}

	repoRoot, bapOut, interOut := setupZSPHookTestEnv(t)

	runHook := func(toolName, sessionID, command string) string {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       toolName,
			"session_id":      sessionID,
			"cwd":             repoRoot,
			"tool_input":      map[string]any{"command": command},
		})
		cmd := exec.Command(interOut)
		cmd.Dir = repoRoot
		cmd.Stdin = bytes.NewReader(payload)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("interceptor failed on %q: %v\n%s", command, err, string(out))
		}
		return string(out)
	}

	sessID := "sess-cchook-sc2-" + time.Now().Format("150405.000")

	// 1. Chained bapedge zsp authorize MUST still be blocked with actionable message.
	outChained := runHook("PowerShell", sessID, `bapedge zsp authorize --client claude-code --session-id `+sessID+` --mission CODE_INSPECTION --goal "Inspect git branch" --actions "git:inspect:read" --resources workspace://current && git status`)
	if !strings.Contains(outChained, `"permissionDecision":"deny"`) && !strings.Contains(outChained, `"permissionDecision": "deny"`) {
		t.Fatalf("expected deny for chained zsp authorize, got: %s", outChained)
	}
	if !strings.Contains(outChained, "standalone command") {
		t.Fatalf("expected actionable standalone guidance in chained denial, got: %s", outChained)
	}

	// 2. Standalone bapedge zsp authorize (even with '&' inside quoted --goal) MUST be allowed.
	outAuth := runHook("PowerShell", sessID, `bapedge zsp authorize --client claude-code --session-id `+sessID+` --mission CODE_INSPECTION --goal "Inspect git branch & recent commits" --actions "git:inspect:read" --resources workspace://current`)
	if !strings.Contains(outAuth, `"permissionDecision":"allow"`) && !strings.Contains(outAuth, `"permissionDecision": "allow"`) {
		t.Fatalf("expected allow for standalone zsp authorize, got: %s", outAuth)
	}

	// Mint the grant using the built bapedge.exe just as the rewritten PowerShell tool execution does.
	mintCmd := exec.Command(bapOut, "zsp", "authorize",
		"--client", "claude-code",
		"--session-id", sessID,
		"--mission", "CODE_INSPECTION",
		"--goal", "Inspect git branch & recent commits",
		"--actions", "git:inspect:read",
		"--resources", "workspace://current",
	)
	mintCmd.Dir = repoRoot
	if mintOut, err := mintCmd.CombinedOutput(); err != nil {
		t.Fatalf("bapedge zsp authorize failed: %v\n%s", err, string(mintOut))
	}

	// 3. Subsequent git status under the same session MUST now be allowed by ZSP + Cedar.
	outGit := runHook("PowerShell", sessID, "git status")
	if !strings.Contains(outGit, `"permissionDecision":"allow"`) && !strings.Contains(outGit, `"permissionDecision": "allow"`) {
		t.Fatalf("expected allow for git status after zsp authorize, got: %s", outGit)
	}
}

func TestInterceptorPreToolUseScenario2CompoundGitStatusAndLog(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows binary verification test")
	}

	repoRoot, bapOut, interOut := setupZSPHookTestEnv(t)
	sessID := "sess-cchook-sc2-compound-" + time.Now().Format("150405.000")

	// 0. UserPromptSubmit for claude-code MUST emit ZSP intent-declaration guidance.
	promptPayload, _ := json.Marshal(map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"app_id":          "claude-code",
		"session_id":      sessID,
		"user_prompt":     "I need to inspect our current git branch status and recent commits.",
	})
	promptCmd := exec.Command(interOut)
	promptCmd.Dir = repoRoot
	promptCmd.Stdin = bytes.NewReader(promptPayload)
	promptOut, err := promptCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("UserPromptSubmit failed: %v\n%s", err, string(promptOut))
	}
	if !strings.Contains(string(promptOut), "bapedge zsp authorize") || !strings.Contains(string(promptOut), `"hookEventName":"UserPromptSubmit"`) {
		t.Fatalf("expected UserPromptSubmit additionalContext with zsp authorize guidance, got: %s", string(promptOut))
	}

	runPreTool := func(command string) string {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       "PowerShell",
			"app_id":          "claude-code",
			"session_id":      sessID,
			"cwd":             repoRoot,
			"tool_input":      map[string]any{"command": command},
		})
		cmd := exec.Command(interOut)
		cmd.Dir = repoRoot
		cmd.Stdin = bytes.NewReader(payload)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("interceptor failed on %q: %v\n%s", command, err, string(out))
		}
		return string(out)
	}

	compoundCmd := "git status --short --branch; git log --oneline -n 10"

	// 1. Ungranted compound command MUST deny and suggest BOTH git:status,git:log + --max-uses 2 + non-self-approval guidance.
	outDeny := runPreTool(compoundCmd)
	if !strings.Contains(outDeny, `"permissionDecision": "deny"`) && !strings.Contains(outDeny, `"permissionDecision":"deny"`) {
		t.Fatalf("expected deny for ungranted compound git command, got: %s", outDeny)
	}
	for _, want := range []string{`git:status,git:log`, `--max-uses 2`, `NOT self-approval`} {
		if !strings.Contains(outDeny, want) {
			t.Fatalf("expected %q in ZSP denial suggestion, got: %s", want, outDeny)
		}
	}

	// 2. Standalone zsp authorize using the exact suggested --goal (with ';') and --actions MUST be allowed by PreToolUse.
	suggestedAuth := `bapedge zsp authorize --session-id "` + sessID + `" --mission TASK_EXECUTION --goal "git status --short --branch; git log --oneline -n 10" --actions "git:status,git:log" --resources workspace://current --max-uses 2`
	outAuth := runPreTool(suggestedAuth)
	if !strings.Contains(outAuth, `"permissionDecision": "allow"`) && !strings.Contains(outAuth, `"permissionDecision":"allow"`) {
		t.Fatalf("expected allow for suggested standalone zsp authorize, got: %s", outAuth)
	}

	// Mint the grant with the built bapedge.exe using those exact actions & max-uses.
	mintCmd := exec.Command(bapOut, "zsp", "authorize",
		"--session-id", sessID,
		"--mission", "TASK_EXECUTION",
		"--goal", compoundCmd,
		"--actions", "git:status,git:log",
		"--resources", "workspace://current",
		"--max-uses", "2",
	)
	mintCmd.Dir = repoRoot
	if mintOut, err := mintCmd.CombinedOutput(); err != nil {
		t.Fatalf("bapedge zsp authorize failed: %v\n%s", err, string(mintOut))
	}

	// 3. Compound command retry MUST now be allowed by both cchook PreToolUse and ZSP checks.
	outAllow := runPreTool(compoundCmd)
	if !strings.Contains(outAllow, `"permissionDecision": "allow"`) && !strings.Contains(outAllow, `"permissionDecision":"allow"`) {
		t.Fatalf("expected allow for compound git command after suggested zsp authorize, got: %s", outAllow)
	}

	// 4. Compound command with an UNGRANTED trailing command MUST still be denied!
	outEscalate := runPreTool("git status --short --branch; git push origin main")
	if !strings.Contains(outEscalate, `"permissionDecision": "deny"`) && !strings.Contains(outEscalate, `"permissionDecision":"deny"`) {
		t.Fatalf("expected deny when compound command adds ungranted git push, got: %s", outEscalate)
	}
}

func TestPreToolUseRewrittenZSPAuthorizeBindsSameSessionPrincipal(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows binary verification test")
	}

	repoRoot, bapOut, interOut := setupZSPHookTestEnv(t)
	sessID := "sess-cchook-rewritten-zsp-" + time.Now().Format("150405.000")

	// Clear ambient session overrides so the child relies strictly on PreToolUse -> bapedge exec propagation.
	t.Setenv("BAP_SESSION_ID", "")
	t.Setenv("LTD_SESSION_ID", "")
	t.Setenv("PATH", filepath.Dir(bapOut)+string(os.PathListSeparator)+os.Getenv("PATH"))

	runPreTool := func(command string) string {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       "PowerShell",
			"app_id":          "claude-code",
			"session_id":      sessID,
			"cwd":             repoRoot,
			"tool_input":      map[string]any{"command": command},
		})
		cmd := exec.Command(interOut)
		cmd.Dir = repoRoot
		cmd.Stdin = bytes.NewReader(payload)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("interceptor failed on %q: %v\n%s", command, err, string(out))
		}
		return string(out)
	}

	// 1. Run zsp authorize WITHOUT --session-id through PreToolUse; hook rewrites it to `bapedge exec --session-id <sessID> ...`.
	outAuth := runPreTool(`bapedge zsp authorize --mission TASK_EXECUTION --goal "Inspect git status" --actions "git:status" --resources workspace://current`)
	var hookResp struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
			UpdatedInput       *struct {
				Command string `json:"command"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(outAuth), &hookResp); err != nil {
		t.Fatalf("failed to parse hook response: %v\n%s", err, outAuth)
	}
	if hookResp.HookSpecificOutput.PermissionDecision != "allow" || hookResp.HookSpecificOutput.UpdatedInput == nil || hookResp.HookSpecificOutput.UpdatedInput.Command == "" {
		t.Fatalf("expected rewritten allow command for zsp authorize, got: %s", outAuth)
	}

	// 2. Execute the exact rewritten `bapedge exec ...` command (without BAP_SESSION_ID in caller env).
	fields := strings.Fields(hookResp.HookSpecificOutput.UpdatedInput.Command)
	if len(fields) < 2 {
		t.Fatalf("unexpected rewritten command: %q", hookResp.HookSpecificOutput.UpdatedInput.Command)
	}
	execCmd := exec.Command(bapOut, fields[1:]...)
	execCmd.Dir = repoRoot
	if execOut, err := execCmd.CombinedOutput(); err != nil {
		t.Fatalf("rewritten bapedge exec failed: %v\n%s", err, string(execOut))
	}

	// 3. Subsequent `git status` under the same sessID MUST now be allowed (proving principal parity).
	outGit := runPreTool("git status")
	if !strings.Contains(outGit, `"permissionDecision": "allow"`) && !strings.Contains(outGit, `"permissionDecision":"allow"`) {
		t.Fatalf("expected allow for git status after rewritten zsp authorize, got: %s", outGit)
	}
}
