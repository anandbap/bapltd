package bapsh

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Core BAP security tests (platform-agnostic, run everywhere)
// ---------------------------------------------------------------------------

func TestBapsh_ParseAndExtractCallCommands(t *testing.T) {
	script := `git status && python a11.py "arg with space" | grep test`
	f, err := Parse(script)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	calls := ExtractCallCommands(f)
	if len(calls) != 3 {
		t.Fatalf("expected 3 command calls, got %d: %+v", len(calls), calls)
	}

	if calls[0][0] != "git" || calls[0][1] != "status" {
		t.Errorf("call 0: expected [git status], got %v", calls[0])
	}
	if calls[1][0] != "python" || calls[1][1] != "a11.py" || calls[1][2] != "arg with space" {
		t.Errorf("call 1: expected [python a11.py 'arg with space'], got %v", calls[1])
	}
	if calls[2][0] != "grep" || calls[2][1] != "test" {
		t.Errorf("call 2: expected [grep test], got %v", calls[2])
	}
}

func TestBapsh_BlocksCredentialAccess(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "cat .env", opts)
	if err == nil {
		t.Fatal("expected credential access to be blocked, got nil")
	}

	if !strings.Contains(err.Error(), "Access to credential file") {
		t.Fatalf("expected credential denial, got: %v", err)
	}
}

func TestBapsh_BlocksBAPAuthorityState(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "cat .bapstate/zsp/pepper.key", opts)
	if err == nil {
		t.Fatal("expected authority state access to be blocked, got nil")
	}

	if !strings.Contains(err.Error(), "BAP authority/state path") {
		t.Fatalf("expected authority path violation, got: %v", err)
	}
}

func TestBapsh_ExecutesReadOnlyEcho(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "echo 'hello from bapsh'", opts)
	if err != nil {
		t.Fatalf("echo should succeed, got: %v", err)
	}

	if !strings.Contains(stdout.String(), "hello from bapsh") {
		t.Fatalf("expected output 'hello from bapsh', got: %q", stdout.String())
	}
}

func TestBapsh_RequiresApprovalForHighRiskToolchain(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "go version", opts)
	if err == nil {
		t.Fatal("expected high-risk toolchain without grant to require approval or grant, got nil")
	}

	if !strings.Contains(err.Error(), "HUMAN APPROVAL REQUIRED") && !strings.Contains(err.Error(), "ZeroStandingPrivilegeViolation") {
		t.Fatalf("expected approval requirement or ZSP violation, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ShellMode detection tests
// ---------------------------------------------------------------------------

func TestBapsh_DetectMode_POSIX(t *testing.T) {
	cases := []struct {
		name   string
		script string
		env    []string
	}{
		{"bash shebang", "#!/bin/bash\nls -al", nil},
		{"sh shebang", "#!/bin/sh\necho hello", nil},
		{"zsh shebang", "#!/usr/bin/env zsh\necho hello", nil},
		{"plain POSIX", "git status && grep foo bar.txt", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectMode(tc.script, tc.env)
			if got != ShellModePOSIX {
				preview := tc.script
				if len(preview) > 40 {
					preview = preview[:40]
				}
				t.Errorf("expected ShellModePOSIX for %q, got %v", preview, got)
			}
		})
	}
}

func TestBapsh_DetectMode_PowerShell(t *testing.T) {
	cases := []struct {
		name   string
		script string
		env    []string
	}{
		{"pwsh shebang", "#!/usr/bin/env pwsh\nGet-ChildItem", nil},
		{"Copy-Item token", "Copy-Item src.txt dst.txt", nil},
		{"Get-Content token", "Get-Content README.md", nil},
		{"Get-ChildItem token", "Get-ChildItem -Path . -Recurse", nil},
		{"PSVersionTable env", "echo hello", []string{"PSModulePath=C:\\PS\\Modules"}},
		{"param block", "param($x)\nWrite-Host $x", nil},
		{"CmdletBinding", "[CmdletBinding()]\nparam($x)", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectMode(tc.script, tc.env)
			if got != ShellModePowerShell {
				t.Errorf("expected ShellModePowerShell for %q, got %v", tc.script, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// looksLikePowerShellScript unit tests
// ---------------------------------------------------------------------------

func TestBapsh_LooksLikePowerShellScript(t *testing.T) {
	yes := []struct {
		name, script string
	}{
		{"Copy-Item", "Copy-Item -Path src -Destination dst"},
		{"Get-Content", "Get-Content -Path README.md"},
		{"Get-ChildItem", "Get-ChildItem -Recurse"},
		{"Write-Host", "Write-Host 'hello'"},
		{"Select-Object", "Get-Process | Select-Object Name, CPU"},
		{"Where-Object", "Get-Service | Where-Object { $_.Status -eq 'Running' }"},
		{"Invoke-Expression", "Invoke-Expression $cmd"},
		{"param block", "param(\n  [string]$Name\n)\nWrite-Host $Name"},
		{"CmdletBinding", "[CmdletBinding()]\nparam()"},
		{"PSVersionTable", "if ($PSVersionTable.PSVersion.Major -ge 7) {}"},
		{"pwsh shebang", "#!/usr/bin/env pwsh\nGet-Item ."},
	}
	for _, tc := range yes {
		t.Run("PS: "+tc.name, func(t *testing.T) {
			if !looksLikePowerShellScript(tc.script) {
				t.Errorf("expected PS detection for: %q", tc.script)
			}
		})
	}

	no := []struct {
		name, script string
	}{
		{"bash shebang", "#!/bin/bash\nls -al"},
		{"sh shebang", "#!/bin/sh\necho ok"},
		{"zsh shebang", "#!/usr/bin/env zsh\necho ok"},
		{"plain git", "git status"},
		{"plain echo", "echo hello world"},
		{"grep", "grep -r foo ."},
	}
	for _, tc := range no {
		t.Run("POSIX: "+tc.name, func(t *testing.T) {
			if looksLikePowerShellScript(tc.script) {
				t.Errorf("expected NOT PS detection for: %q", tc.script)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// splitPowerShellStatements unit tests
// ---------------------------------------------------------------------------

func TestBapsh_SplitPowerShellStatements(t *testing.T) {
	script := "Get-Item .; Get-ChildItem -Recurse\nWrite-Host 'done'"
	stmts := splitPowerShellStatements(script)
	if len(stmts) != 3 {
		t.Fatalf("expected 3 statements, got %d: %v", len(stmts), stmts)
	}
	if strings.TrimSpace(stmts[0]) != "Get-Item ." {
		t.Errorf("stmt 0: %q", stmts[0])
	}
}

func TestBapsh_SplitPowerShellStatements_RespectsQuotes(t *testing.T) {
	script := `Write-Host "hello; world"` + "\nGet-Item ."
	stmts := splitPowerShellStatements(script)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d: %v", len(stmts), stmts)
	}
	// The semicolon inside the double-quoted string must NOT split
	if !strings.Contains(stmts[0], "hello; world") {
		t.Errorf("quoted semicolon was incorrectly split: %q", stmts[0])
	}
}

// ---------------------------------------------------------------------------
// tokenizePowerShellLine unit tests
// ---------------------------------------------------------------------------

func TestBapsh_TokenizePowerShellLine(t *testing.T) {
	cases := []struct {
		line   string
		expect []string
	}{
		{"Copy-Item src.txt dst.txt", []string{"Copy-Item", "src.txt", "dst.txt"}},
		{`Get-Content "my file.txt"`, []string{"Get-Content", "my file.txt"}},
		{"Get-Content README.md | Select-String foo", []string{"Get-Content", "README.md"}},
		{"Remove-Item -Path old.txt -Force", []string{"Remove-Item", "-Path", "old.txt", "-Force"}},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			got := tokenizePowerShellLine(tc.line)
			if len(got) != len(tc.expect) {
				t.Fatalf("expected %v, got %v", tc.expect, got)
			}
			for i, w := range tc.expect {
				if got[i] != w {
					t.Errorf("token[%d]: want %q, got %q", i, w, got[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Windows-only: POSIX alias shim tests
// ---------------------------------------------------------------------------

func TestBapsh_ResolveWindowsArgs_Aliases(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// dir is a cmd.exe builtin and never exists as a standalone binary in PATH
	got, ok := resolveWindowsArgs([]string{"dir", "/w"})
	if !ok {
		t.Fatal("expected rewrite for dir on Windows")
	}
	if len(got) < 5 || got[0] != "cmd.exe" || got[4] != "dir" {
		t.Errorf("unexpected rewrite for dir: %v", got)
	}
	if got[len(got)-1] != "/w" {
		t.Errorf("expected user arg /w preserved, got %v", got)
	}

	// ls: if Git/MSYS is not in PATH, it must rewrite to dir
	if _, err := exec.LookPath("ls"); err != nil {
		got, ok = resolveWindowsArgs([]string{"ls", "-al"})
		if !ok {
			t.Fatal("expected rewrite for ls on Windows when not in PATH")
		}
		if got[4] != "dir" {
			t.Errorf("expected 'dir', got %v", got)
		}
	} else {
		// If ls is found in PATH (e.g. Git for Windows on CI runner), it should NOT be rewritten
		_, ok = resolveWindowsArgs([]string{"ls", "-al"})
		if ok {
			t.Error("ls binary is in PATH, should not be rewritten")
		}
	}

	// git is in PATH → no rewrite
	_, ok = resolveWindowsArgs([]string{"git", "status"})
	if ok {
		t.Error("git is in PATH, should not be rewritten")
	}
}

// ---------------------------------------------------------------------------
// Cross-platform: PowerShell cmdlet alias resolution
// ---------------------------------------------------------------------------

func TestBapsh_ResolvePowerShellCmdletArgs_KnownCmdlet(t *testing.T) {
	// Copy-Item should be recognised regardless of OS.
	// If pwsh is unavailable we expect a descriptive error (not exit-127).
	got, ok, err := resolvePowerShellCmdletArgs([]string{"Copy-Item", "src.txt", "dst.txt"})
	if !ok && err != nil {
		// pwsh not installed → error should be descriptive, not exit-127
		if !strings.Contains(err.Error(), "pwsh") && !strings.Contains(err.Error(), "PowerShell") {
			t.Errorf("expected descriptive PS install error, got: %v", err)
		}
		return
	}
	if !ok {
		t.Fatal("expected Copy-Item to be recognised as a PS cmdlet")
	}
	// Should have been rewritten to pwsh -NoProfile -NonInteractive -Command "..."
	if len(got) < 4 {
		t.Fatalf("too few args: %v", got)
	}
	if !strings.Contains(strings.ToLower(got[0]), "pwsh") && !strings.Contains(strings.ToLower(got[0]), "powershell") {
		t.Errorf("expected pwsh binary as first arg, got %q", got[0])
	}
}

func TestBapsh_ResolvePowerShellCmdletArgs_GetContent(t *testing.T) {
	_, ok, err := resolvePowerShellCmdletArgs([]string{"Get-Content", "README.md"})
	if !ok && err == nil {
		t.Fatal("expected Get-Content to match PS cmdlets")
	}
	// Either it resolved (ok=true) or pwsh is absent (err != nil with description)
	if err != nil && !strings.Contains(err.Error(), "PowerShell") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBapsh_ResolvePowerShellCmdletArgs_PlainBinary(t *testing.T) {
	_, ok, err := resolvePowerShellCmdletArgs([]string{"git", "status"})
	if ok || err != nil {
		t.Errorf("git should not be treated as a PS cmdlet: ok=%v err=%v", ok, err)
	}
}

// ---------------------------------------------------------------------------
// BAP security: PowerShell mode must still block credentials
// ---------------------------------------------------------------------------

func TestBapsh_PowerShell_BlocksCredentialAccess(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		Mode:          ShellModePowerShell,
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	// Get-Content .env should be blocked by BAP pre-flight even in PS mode
	err := Run(ctx, "Get-Content .env", opts)
	if err == nil {
		t.Fatal("expected credential access to be blocked in PowerShell mode, got nil")
	}
	if !strings.Contains(err.Error(), "credential file") && !strings.Contains(err.Error(), "POLICY DENIAL") {
		t.Fatalf("expected credential denial, got: %v", err)
	}
}

func TestBapsh_PowerShell_BlocksBAPAuthorityState(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	opts := Options{
		Mode:          ShellModePowerShell,
		SessionID:     "sess-test-bapsh",
		ClientType:    "claude-code",
		WorkspaceRoot: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
	}

	err := Run(ctx, "Get-Content .bapstate/zsp/pepper.key", opts)
	if err == nil {
		t.Fatal("expected BAP authority access to be blocked in PowerShell mode, got nil")
	}
	if !strings.Contains(err.Error(), "authority/state path") && !strings.Contains(err.Error(), "credential file") {
		t.Fatalf("expected authority path violation, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ParseShellHint unit tests
// ---------------------------------------------------------------------------

func TestBapsh_ParseShellHint(t *testing.T) {
	cases := []struct {
		hint   string
		expect ShellMode
	}{
		// PowerShell
		{"pwsh", ShellModePowerShell},
		{"PWSH", ShellModePowerShell},
		{"powershell", ShellModePowerShell},
		{"PowerShell", ShellModePowerShell},
		// POSIX
		{"bash", ShellModePOSIX},
		{"Bash", ShellModePOSIX},
		{"sh", ShellModePOSIX},
		{"zsh", ShellModePOSIX},
		{"cmd", ShellModePOSIX},
		{"bapsh", ShellModePOSIX},
		// Auto / unknown
		{"auto", ShellModeAuto},
		{"", ShellModeAuto},
		{"fish", ShellModeAuto},
		{"unknown", ShellModeAuto},
	}
	for _, tc := range cases {
		t.Run(tc.hint, func(t *testing.T) {
			got := ParseShellHint(tc.hint)
			if got != tc.expect {
				t.Errorf("ParseShellHint(%q) = %v, want %v", tc.hint, got, tc.expect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// PowerShell resolvePowerShellExe
// ---------------------------------------------------------------------------

func TestBapsh_ResolvePowerShellExe(t *testing.T) {
	exe := resolvePowerShellExe()
	t.Logf("resolvePowerShellExe() = %q (GOOS=%s)", exe, runtime.GOOS)
	// We don't fail if pwsh is absent (CI may not have it),
	// but if it IS found, the path must exist on disk.
	if exe != "" {
		if _, err := exec.LookPath(exe); err != nil {
			// LookPath fails for absolute paths that don't match PATH entries;
			// fall back to os.Stat.
			if _, statErr := os.Stat(exe); statErr != nil {
				t.Errorf("resolvePowerShellExe returned %q but it is not found: %v", exe, statErr)
			}
		}
	}
}
