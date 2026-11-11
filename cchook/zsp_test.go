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

func TestInterceptorPreToolUseBlocksScenario1WithBuiltBroker(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows binary verification test")
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
	bapedgeOut := filepath.Join(tmpBin, "bap-broker-test.exe")
	buildCmd := exec.Command("go", "build", "-C", "../bap-edge", "-o", bapedgeOut, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build bapedge.exe for test: %v\n%s", err, string(out))
	}

	zspDir := t.TempDir()
	t.Setenv("BAP_ZSP_DIR", zspDir)
	t.Setenv("BAP_ZSP", "enforce")
	t.Setenv("BAP_NON_INTERACTIVE", "1")
	t.Setenv("BAP_EDGE_BIN", bapedgeOut)
	t.Setenv("PATH", tmpBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Build interceptor binary into tmpBin
	interOut := filepath.Join(tmpBin, "interceptor.exe")
	buildInter := exec.Command("go", "build", "-o", interOut, ".")
	if out, err := buildInter.CombinedOutput(); err != nil {
		t.Fatalf("failed to build interceptor.exe for test: %v\n%s", err, string(out))
	}

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

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	stateDir := t.TempDir()
	pepHome := t.TempDir()

	bapOut := filepath.Join(binDir, "bapedge.exe")
	buildBap := exec.Command("go", "build", "-C", filepath.Join(repoRoot, "bap-edge"), "-o", bapOut, ".")
	if out, err := buildBap.CombinedOutput(); err != nil {
		t.Fatalf("build bapedge failed: %v\n%s", err, string(out))
	}

	interOut := filepath.Join(binDir, "interceptor.exe")
	buildInter := exec.Command("go", "build", "-o", interOut, ".")
	if out, err := buildInter.CombinedOutput(); err != nil {
		t.Fatalf("build interceptor failed: %v\n%s", err, string(out))
	}

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LTD_STATE_DIR", stateDir)
	t.Setenv("BAP_PEP_HOME", pepHome)
	t.Setenv("BAP_ZSP_ENABLED", "1")
	t.Setenv("LTD_ENFORCE_MODE", "enforce")
	t.Setenv("BAP_MODE", "enforce")
	t.Setenv("LTD_SOURCE", "claude-code")

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
