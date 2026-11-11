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
