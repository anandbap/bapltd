// Package bapsh provides a BAP-aware restricted shell that routes command
// execution through the ZSP authz layer before delegating to the appropriate
// platform shell engine.
//
// # Shell Engine Selection
//
// bapsh supports three execution modes (ShellMode), selected automatically or
// explicitly via Options.Mode:
//
//   - ShellModePOSIX    – mvdan.cc/sh/v3 POSIX interpreter; handles bash, sh,
//                         and zsh scripts that use POSIX-compatible syntax.
//   - ShellModePowerShell – delegates the whole script to pwsh (PowerShell 7+)
//                           or powershell.exe (Windows PS 5.1 fallback).
//   - ShellModeAuto     – (default) detects the best engine from the runtime
//                         environment ($SHELL, $PSVersionTable, OS) and from
//                         the script content (Verb-Noun patterns, shebang).
//
// # BAP Policy Enforcement (all modes)
//
//  1. Credential / authority-path guard – checked against the original logical
//     command tokens; never bypassed by platform shims.
//  2. IsLocalReadOnlyCommand – grants read-only commands automatically.
//  3. ZSP grant checks  – mutating commands require a task grant or HITL
//     approval (bapedge zsp approve <req-id>).
//
// PowerShell commands are classified using the existing authz.ClassifyCommand
// and authz.Decompose infrastructure (classifier.go already knows Copy-Item,
// Get-Content, etc.) before being handed to pwsh for execution.
package bapsh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"bap-edge/internal/authz"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// ---------------------------------------------------------------------------
// ShellMode
// ---------------------------------------------------------------------------

// ShellMode selects which shell engine bapsh uses to execute a script.
type ShellMode int

const (
	// ShellModeAuto detects the best engine from the runtime environment and
	// script content.  This is the default when Options.Mode is zero.
	ShellModeAuto ShellMode = iota

	// ShellModePOSIX uses the embedded mvdan.cc/sh/v3 POSIX interpreter.
	// Compatible with bash, sh, and most zsh scripts.  Commands that are not
	// found as POSIX binaries on the host OS are shimmed transparently:
	//   - Windows: POSIX aliases (ls→dir, cat→type, cp→copy, …) via cmd.exe.
	//   - Any OS:  missing PowerShell cmdlets produce a clear error rather
	//              than the opaque exit-127.
	ShellModePOSIX

	// ShellModePowerShell delegates the entire script to pwsh (PowerShell 7+)
	// or, on Windows only, falls back to powershell.exe (PS 5.1).
	// BAP policy is still evaluated per-statement before execution.
	ShellModePowerShell
)

// ParseShellHint converts a human-readable shell name from the --shell or
// --shell-hint CLI flag into a ShellMode.  Agents should always pass one of
// these values explicitly rather than relying on auto-detection.
//
// Accepted values (case-insensitive):
//
//	"auto"              → ShellModeAuto  (default; heuristic detection)
//	"bash" "sh" "zsh"  → ShellModePOSIX
//	"cmd"              → ShellModePOSIX  (Windows POSIX-alias shim handles cmd.exe built-ins)
//	"bapsh"            → ShellModePOSIX  (explicit bapsh = POSIX engine)
//	"pwsh" "powershell"→ ShellModePowerShell
func ParseShellHint(hint string) ShellMode {
	switch strings.ToLower(strings.TrimSpace(hint)) {
	case "pwsh", "powershell":
		return ShellModePowerShell
	case "bash", "sh", "zsh", "cmd", "bapsh":
		return ShellModePOSIX
	default:
		return ShellModeAuto
	}
}

// ---------------------------------------------------------------------------
// Platform alias tables
// ---------------------------------------------------------------------------

// windowsAliases maps POSIX command names to their Windows cmd.exe shims.
// Used only on Windows when the POSIX binary is absent from PATH.
var windowsAliases = map[string][]string{
	"ls":    {"cmd.exe", "/d", "/s", "/c", "dir"},
	"dir":   {"cmd.exe", "/d", "/s", "/c", "dir"},
	"cat":   {"cmd.exe", "/d", "/s", "/c", "type"},
	"cp":    {"cmd.exe", "/d", "/s", "/c", "copy"},
	"mv":    {"cmd.exe", "/d", "/s", "/c", "move"},
	"rm":    {"cmd.exe", "/d", "/s", "/c", "del"},
	"mkdir": {"cmd.exe", "/d", "/s", "/c", "mkdir"},
	"rmdir": {"cmd.exe", "/d", "/s", "/c", "rmdir"},
	"clear": {"cmd.exe", "/d", "/s", "/c", "cls"},
	"grep":  nil, // findstr differs too much; keep as-is
	"pwd":   nil, // handled by mvdan.cc builtin
}

// powershellCmdlets is the canonical set of PowerShell-native command names
// (all lowercase) that mvdan.cc/sh/v3 cannot parse or execute.
// authz/classifier.go already knows all of these for policy classification;
// this map drives the execution-path decision in bapsh's exec handler.
var powershellCmdlets = map[string]bool{
	// ── File & content ────────────────────────────────────────────────────
	"copy-item": true, "cpi": true,
	"move-item": true, "mi": true,
	"remove-item": true, "ri": true,
	"new-item": true, "ni": true,
	"get-content": true, "gc": true,
	"set-content": true, "sc": true,
	"add-content": true, "ac": true,
	"get-childitem": true, "gci": true,
	"out-file": true,
	// ── Path helpers ──────────────────────────────────────────────────────
	"test-path": true, "resolve-path": true, "join-path": true,
	"split-path": true, "get-location": true, "set-location": true,
	"push-location": true, "pop-location": true,
	// ── Output / formatting ───────────────────────────────────────────────
	"write-output": true, "write-host": true, "write-error": true,
	"write-warning": true, "write-verbose": true, "write-debug": true,
	"format-table": true, "ft": true,
	"format-list": true, "fl": true,
	"format-wide": true, "fw": true,
	"out-string": true, "out-null": true, "out-host": true,
	"out-default": true,
	"tee-object": true, "tee": true,
	// ── Object pipeline ───────────────────────────────────────────────────
	"where-object": true, "where": true,
	"foreach-object": true,
	"select-object": true, "select": true,
	"sort-object": true, "sort": true,
	"group-object": true, "group": true,
	"measure-object": true, "measure": true,
	"compare-object": true,
	"select-string": true, "sls": true,
	// ── Conversion / serialisation ────────────────────────────────────────
	"convertto-json": true, "convertfrom-json": true,
	"convertto-csv": true, "convertfrom-csv": true,
	"convertto-xml": true, "convertfrom-xml": true,
	"convertto-html": true,
	// ── Environment / system ──────────────────────────────────────────────
	"get-command": true, "get-member": true, "get-help": true,
	"get-alias": true, "set-alias": true, "new-alias": true,
	"get-variable": true, "set-variable": true, "new-variable": true,
	"get-process": true, "stop-process": true, "start-process": true,
	"get-service": true, "start-service": true, "stop-service": true,
	"get-date": true, "start-sleep": true, "sleep": true,
	"measure-command": true,
	"invoke-expression": true, "iex": true,
	"invoke-command": true, "icm": true,
	"invoke-webrequest": true, "iwr": true,
	"invoke-restmethod": true, "irm": true,
	"get-module": true, "import-module": true, "remove-module": true,
	"get-psdrive": true, "new-psdrive": true,
	"get-acl": true, "set-acl": true,
	"register-objectevent": true, "unregister-event": true,
	"clear-host": true, "clear": true,
}

// ---------------------------------------------------------------------------
// Shell-environment detection
// ---------------------------------------------------------------------------

// isPowerShellEnv reports whether the current process is running inside an
// active PowerShell session (either pwsh or powershell.exe as parent).
func isPowerShellEnv() bool {
	// PowerShell sets $PSVersionTable; its child processes inherit PSVERSIONTABLE_VERSION
	// (not standard, but we check the caller binary name as well).
	if os.Getenv("PSVersionTable") != "" || os.Getenv("PSVERSIONTABLE_VERSION") != "" {
		return true
	}
	// On Windows the parent shell is often detectable via the caller binary recorded
	// in the BAP receipt.  Here we check if the current process's parent is pwsh.
	// We approximate by checking COMSPEC + PSModulePath (PS always sets PSModulePath).
	if os.Getenv("PSModulePath") != "" {
		return true
	}
	return false
}

// shellFromEnv returns the shell binary name from $SHELL (Linux/macOS) or a
// best-guess for Windows ("powershell" or "cmd").
func shellFromEnv() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return strings.ToLower(filepath.Base(sh))
	}
	if runtime.GOOS == "windows" {
		if isPowerShellEnv() {
			return "powershell"
		}
		return "cmd"
	}
	return "sh"
}

// looksLikePowerShellScript reports whether the script string is likely a
// PowerShell script based on heuristics:
//
//   - starts with a #! that names pwsh or powershell
//   - contains a Verb-Noun pattern (e.g. Get-Item, Copy-Item, Write-Host)
//   - contains $PSVersionTable
//   - uses param(), begin { }, process { }, end { } blocks
//   - uses [CmdletBinding()] attribute
func looksLikePowerShellScript(script string) bool {
	lower := strings.ToLower(script)

	// Explicit shebang
	if strings.HasPrefix(lower, "#!/") {
		line := strings.SplitN(lower, "\n", 2)[0]
		if strings.Contains(line, "pwsh") || strings.Contains(line, "powershell") {
			return true
		}
		// Explicit bash/sh/zsh shebang → definitely NOT PowerShell
		if strings.Contains(line, "bash") || strings.Contains(line, "zsh") || strings.Contains(line, " sh") {
			return false
		}
	}

	// Strong PowerShell indicators
	if strings.Contains(lower, "$psversiontable") ||
		strings.Contains(lower, "[cmdletbinding") ||
		strings.Contains(lower, "param(") {
		return true
	}

	// Scan tokens for Verb-Noun cmdlet pattern  (e.g. Get-Item, Copy-Item)
	// We look for known cmdlet names from powershellCmdlets map.
	for _, token := range strings.Fields(script) {
		clean := strings.ToLower(strings.Trim(token, "();|&\t\r\n\"'`"))
		if powershellCmdlets[clean] {
			return true
		}
	}
	return false
}

// detectMode picks the ShellMode when Options.Mode == ShellModeAuto.
func detectMode(script string, envList []string) ShellMode {
	// ── 1. Explicit shebang wins over everything ──────────────────────────
	// A script that declares its own interpreter is authoritative.
	lower := strings.ToLower(strings.TrimSpace(script))
	if strings.HasPrefix(lower, "#!") {
		line := strings.SplitN(lower, "\n", 2)[0]
		if strings.Contains(line, "pwsh") || strings.Contains(line, "powershell") {
			return ShellModePowerShell
		}
		if strings.Contains(line, "bash") || strings.Contains(line, "zsh") || strings.Contains(line, " sh") {
			return ShellModePOSIX
		}
	}

	// ── 2. PowerShell in provided env list (e.g. from Options.Env) ───────
	for _, e := range envList {
		if strings.HasPrefix(e, "PSModulePath=") || strings.HasPrefix(e, "PSVersionTable=") {
			return ShellModePowerShell
		}
	}

	// ── 3. Script content heuristics (before OS environment check) ────────
	// Script content is a stronger signal than the ambient shell environment
	// because an agent may be running inside PowerShell but issuing POSIX scripts.
	if looksLikePowerShellScript(script) {
		return ShellModePowerShell
	}

	// ── 4. Shell environment (ambient detection) ──────────────────────────
	// Only used as a tiebreaker when the script has no strong content signal.
	sh := shellFromEnv()
	if sh == "powershell" || sh == "pwsh" {
		// Even inside a PS session, prefer POSIX for plain POSIX-looking scripts
		// (the content check above didn't match anything PS-specific).
		// Fall through to ShellModePOSIX so that `echo hello` from Claude doesn't
		// get routed to pwsh unnecessarily.
		_ = sh
	}

	return ShellModePOSIX
}

// ---------------------------------------------------------------------------
// PowerShell binary resolution
// ---------------------------------------------------------------------------

// resolvePowerShellExe returns the path to the best available PowerShell
// binary: pwsh (PowerShell 7+) is preferred over powershell.exe (PS 5.1).
// Returns "" when no PowerShell is available on the host.
func resolvePowerShellExe() string {
	// 1. PATH lookup (works on Linux, macOS, and Windows)
	for _, name := range []string{"pwsh", "pwsh.exe", "powershell", "powershell.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	// 2. Well-known Windows install locations (not in PATH sometimes)
	if runtime.GOOS == "windows" {
		candidates := []string{
			`C:\Program Files\PowerShell\7\pwsh.exe`,
			`C:\Program Files\PowerShell\7-preview\pwsh.exe`,
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	// 3. macOS Homebrew / package-manager locations
	if runtime.GOOS == "darwin" {
		candidates := []string{
			"/usr/local/bin/pwsh",
			"/opt/homebrew/bin/pwsh",
			"/opt/local/bin/pwsh",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	// 4. Linux snap / package-manager locations
	if runtime.GOOS == "linux" {
		candidates := []string{
			"/snap/bin/pwsh",
			"/usr/bin/pwsh",
			"/usr/local/bin/pwsh",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// POSIX exec-handler shims
// ---------------------------------------------------------------------------

// resolveWindowsArgs rewrites a POSIX command to its Windows cmd.exe
// equivalent when the binary is absent from PATH on Windows.
// Returns (rewrittenArgs, true) on rewrite, (original, false) otherwise.
func resolveWindowsArgs(args []string) ([]string, bool) {
	if runtime.GOOS != "windows" || len(args) == 0 {
		return args, false
	}
	cmd := strings.ToLower(filepath.Base(args[0]))
	cmd = strings.TrimSuffix(cmd, ".exe")

	// Binary already findable → no rewrite needed
	if _, err := exec.LookPath(args[0]); err == nil {
		return args, false
	}

	replacement, known := windowsAliases[cmd]
	if !known || replacement == nil {
		return args, false
	}

	rewritten := make([]string, len(replacement))
	copy(rewritten, replacement)
	rewritten = append(rewritten, args[1:]...)
	return rewritten, true
}

// resolvePowerShellCmdletArgs detects a PowerShell cmdlet token in args[0] and
// rewrites the invocation to run via pwsh.  Called only in POSIX mode when the
// host's exec.LookPath cannot find the cmdlet as a binary.
//
// Returns (rewrittenArgs, true, nil)        on successful rewrite.
// Returns (original, false, nil)            when args[0] is not a PS cmdlet.
// Returns (original, false, descriptiveErr) when PS is unavailable.
func resolvePowerShellCmdletArgs(args []string) ([]string, bool, error) {
	if len(args) == 0 {
		return args, false, nil
	}
	cmdLower := strings.ToLower(filepath.Base(args[0]))
	cmdLower = strings.TrimSuffix(cmdLower, ".exe")

	if !powershellCmdlets[cmdLower] {
		return args, false, nil
	}

	psExe := resolvePowerShellExe()
	if psExe == "" {
		return args, false, fmt.Errorf(
			"BAP BAPSH: PowerShell cmdlet %q requires pwsh to be installed "+
				"(not found in PATH or well-known locations).\n"+
				"  Linux/macOS: https://learn.microsoft.com/powershell/scripting/install/installing-powershell\n"+
				"  Windows:     winget install Microsoft.PowerShell",
			args[0],
		)
	}

	cmdStr := strings.Join(args, " ")
	rewritten := []string{psExe, "-NoProfile", "-NonInteractive", "-Command", cmdStr}
	return rewritten, true, nil
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// Options configure the BAP-aware restricted shell execution.
type Options struct {
	// Mode selects the shell engine.  Zero value (ShellModeAuto) is recommended.
	Mode          ShellMode
	SessionID     string
	ClientType    string
	WorkspaceRoot string
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	Env           []string
	Timeout       time.Duration
}

// ---------------------------------------------------------------------------
// Parse / ExtractCallCommands (POSIX AST helpers)
// ---------------------------------------------------------------------------

// Parse parses a shell script string into a syntax.File AST.
func Parse(script string) (*syntax.File, error) {
	p := syntax.NewParser()
	f, err := p.Parse(strings.NewReader(script), "")
	if err != nil {
		return nil, fmt.Errorf("bapsh parse error: %w", err)
	}
	return f, nil
}

// ExtractCallCommands walks the AST and returns all top-level command invocations.
func ExtractCallCommands(f *syntax.File) [][]string {
	var calls [][]string
	syntax.Walk(f, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			var cmdArgs []string
			for _, word := range call.Args {
				var sb strings.Builder
				for _, part := range word.Parts {
					if lit, ok := part.(*syntax.Lit); ok {
						sb.WriteString(lit.Value)
					} else if sval, ok := part.(*syntax.SglQuoted); ok {
						sb.WriteString(sval.Value)
					} else if dval, ok := part.(*syntax.DblQuoted); ok {
						for _, p := range dval.Parts {
							if dlit, ok := p.(*syntax.Lit); ok {
								sb.WriteString(dlit.Value)
							}
						}
					}
				}
				cmdArgs = append(cmdArgs, sb.String())
			}
			if len(cmdArgs) > 0 && cmdArgs[0] != "" {
				calls = append(calls, cmdArgs)
			}
		}
		return true
	})
	return calls
}

// ---------------------------------------------------------------------------
// BAP policy helpers (shared by both POSIX and PowerShell paths)
// ---------------------------------------------------------------------------

// bapGuard runs credential-access, authority-path, and ZSP checks against the
// original logical command (originalArgs) and returns nil when the command is
// permitted.  On success the caller should execute using the (possibly
// platform-rewritten) execArgs.
func bapGuard(
	originalArgs []string,
	ws, sess, client string,
	timeout time.Duration,
) error {
	cmdName := originalArgs[0]
	fullLine := strings.Join(originalArgs, " ")

	// 1. Hard-deny credential files and BAP authority paths
	for _, arg := range originalArgs {
		if authz.IsBAPAuthorityPath(arg) {
			return fmt.Errorf("BAP ZERO-TRUST SECURITY VIOLATION: Access to BAP authority/state path %q is strictly forbidden", arg)
		}
		lower := strings.ToLower(filepath.ToSlash(arg))
		if strings.Contains(lower, ".env") ||
			strings.Contains(lower, ".aws/credentials") ||
			strings.Contains(lower, ".ssh/id_") {
			return fmt.Errorf("BAP POLICY DENIAL: Access to credential file %q is permanently denied", arg)
		}
	}

	// 2. Read-only inspection within workspace needs no grant
	cmdArgs := ""
	if len(originalArgs) > 1 {
		cmdArgs = strings.Join(originalArgs[1:], " ")
	}
	if authz.IsLocalReadOnlyCommand(fullLine, cmdName, cmdArgs, ws) {
		return nil // permitted — no grant consumed
	}

	// 3. ZSP grant / HITL flow for mutating or high-risk commands
	zspDir := authz.ResolveZSPDir()
	zspChecks := authz.ResolveZSPCommandChecks(fullLine, cmdName, cmdArgs, "", "", ws)
	_, _, _, zspErr := authz.AuthorizeSessionCommandBatch(
		zspDir, sess, client, fullLine, ws, zspChecks, true,
		[]string{fmt.Sprintf("broker:%d", os.Getpid())},
		"bapsh",
	)
	if zspErr == nil {
		return nil // grant obtained
	}

	// Collect what was denied / needs approval
	var reqActions, reqResources []string
	for _, c := range zspChecks {
		reqActions = append(reqActions, c.Action)
		res := c.CanonicalResource
		if res == "" || !c.EscapesWorkspace {
			res = "workspace://current"
		}
		reqResources = append(reqResources, res)
	}

	// Load permission policy for decision routing
	var policy *authz.PermissionPolicy
	if _, _, _, secret, sErr := authz.EnsureSessionPrincipal(zspDir, sess, client); sErr == nil {
		policy, _ = authz.LoadPermissionPolicy(zspDir, secret)
	}
	if policy == nil {
		policy, _ = authz.DefaultPermissionPolicy()
	}

	if policy != nil {
		decision := policy.Evaluate(reqActions, reqResources)
		if len(decision.Denied) > 0 {
			return fmt.Errorf("BAP POLICY DENIAL: Action(s) %s permanently denied by enterprise policy",
				authz.FormatPairs(decision.Denied))
		}
		if len(decision.NeedsApproval) > 0 || errors.Is(zspErr, authz.ErrHighRiskApprovalRequired) {
			p, rErr := authz.RaisePendingApproval(zspDir, authz.PendingApproval{
				SessionID:           sess,
				RequestingSessionID: sess,
				ClientType:          client,
				Mission:             "TASK_EXECUTION",
				Goal:                fullLine,
				Actions:             reqActions,
				Resources:           reqResources,
				MaxUses:             1,
				TTLSeconds:          300,
				Reason: fmt.Sprintf(
					"high-risk execution in bapsh requires human approval: %s",
					authz.FormatPairs(decision.NeedsApproval)),
			})
			if rErr == nil && p != nil {
				return fmt.Errorf(
					"HUMAN APPROVAL REQUIRED: Action(s) require verified human approval.\n"+
						"Pending Request ID: %s\n"+
						"DEVELOPER ACTION: Run 'bapedge zsp approve %s' in your terminal.\n"+
						"AGENT: Stop and ask the developer to approve request %s. Do NOT run bapedge zsp authorize; retry once approved",
					p.ID, p.ID, p.ID)
			}
			return errors.New("HUMAN APPROVAL REQUIRED: High-risk action requires interactive human approval")
		}
	}
	return fmt.Errorf("ZeroStandingPrivilegeViolation: %w", zspErr)
}

// ---------------------------------------------------------------------------
// Run — main entry point
// ---------------------------------------------------------------------------

// Run executes a shell script string within a BAP-governed restricted interpreter.
//
// Shell engine selection (opts.Mode):
//   - ShellModeAuto       → auto-detect from environment and script content
//   - ShellModePOSIX      → mvdan.cc/sh/v3 (bash/sh/zsh-compatible)
//   - ShellModePowerShell → pwsh / powershell.exe
func Run(ctx context.Context, script string, opts Options) error {
	ws := opts.WorkspaceRoot
	if ws == "" {
		ws = authz.GetWorkspaceRoot()
	}
	sess := opts.SessionID
	if sess == "" {
		sess = "sess-bapsh-interactive"
	}
	client := opts.ClientType
	if client == "" {
		client = "agent"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	envList := opts.Env
	if len(envList) == 0 {
		envList = os.Environ()
	}

	// Resolve the shell mode
	mode := opts.Mode
	if mode == ShellModeAuto {
		mode = detectMode(script, envList)
	}

	switch mode {
	case ShellModePowerShell:
		return runPowerShell(ctx, script, opts, ws, sess, client, timeout, envList)
	default:
		return runPOSIX(ctx, script, opts, ws, sess, client, timeout, envList)
	}
}

// ---------------------------------------------------------------------------
// runPOSIX — mvdan.cc/sh/v3 path (bash / sh / zsh)
// ---------------------------------------------------------------------------

func runPOSIX(
	ctx context.Context,
	script string,
	opts Options,
	ws, sess, client string,
	timeout time.Duration,
	envList []string,
) error {
	f, err := Parse(script)
	if err != nil {
		return err
	}

	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	execHandler := func(hCtx context.Context, args []string) error {
		if len(args) == 0 {
			return nil
		}

		// originalArgs = what the script wrote ("ls", "Copy-Item", …)
		// Used for BAP policy classification so the authz layer sees semantic
		// intent, not the platform shim (cmd.exe /d /s /c dir).
		originalArgs := args

		// ── Platform-specific execution-path resolution ──────────────────
		//
		// Priority:
		//  1. Windows POSIX alias shim (ls→cmd /c dir, cat→cmd /c type, …)
		//  2. PowerShell cmdlet delegation (Copy-Item, Get-Content, …)
		//     Works on any OS where pwsh is installed.

		if rewritten, ok := resolveWindowsArgs(args); ok {
			// Windows POSIX alias: exec via cmd.exe shim
			args = rewritten
		} else if rewritten, ok, psErr := resolvePowerShellCmdletArgs(args); psErr != nil {
			// PowerShell cmdlet detected but pwsh is not installed
			return psErr
		} else if ok {
			// PowerShell cmdlet: delegate to pwsh -Command "…"
			args = rewritten
		}

		// ── BAP policy guard (always against originalArgs) ────────────────
		if err := bapGuard(originalArgs, ws, sess, client, timeout); err != nil {
			// Read-only? bapGuard returned nil — but we still need to exec.
			// Non-nil means denied/needs-approval: return the error.
			return err
		}

		return interp.DefaultExecHandler(timeout)(hCtx, args)
	}

	var runnerOpts []interp.RunnerOption
	runnerOpts = append(runnerOpts, interp.ExecHandler(execHandler))
	runnerOpts = append(runnerOpts, interp.Dir(ws))
	runnerOpts = append(runnerOpts, interp.StdIO(opts.Stdin, opts.Stdout, opts.Stderr))
	runnerOpts = append(runnerOpts, interp.Env(expand.ListEnviron(envList...)))

	runner, err := interp.New(runnerOpts...)
	if err != nil {
		return fmt.Errorf("bapsh init error: %w", err)
	}
	return runner.Run(subCtx, f)
}

// ---------------------------------------------------------------------------
// runPowerShell — pwsh / powershell.exe path
// ---------------------------------------------------------------------------

// runPowerShell executes the script via pwsh, applying BAP policy per
// statement before invoking the subprocess.
//
// Because PowerShell scripts cannot be AST-walked by mvdan.cc/sh/v3, we apply
// a statement-level pre-check by splitting on semicolons and newlines and
// running bapGuard on each apparent command before handing the whole script to
// pwsh.  This is a best-effort pre-flight: a fully policy-compliant script
// that generates no pre-flight violations is then executed atomically by pwsh.
func runPowerShell(
	ctx context.Context,
	script string,
	opts Options,
	ws, sess, client string,
	timeout time.Duration,
	envList []string,
) error {
	psExe := resolvePowerShellExe()
	if psExe == "" {
		return fmt.Errorf(
			"BAP BAPSH: ShellModePowerShell requested but pwsh/powershell is not installed.\n"+
				"  Linux/macOS: https://learn.microsoft.com/powershell/scripting/install/installing-powershell\n"+
				"  Windows:     winget install Microsoft.PowerShell",
		)
	}

	// ── Pre-flight BAP policy check per logical statement ─────────────────
	// Split the script into logical lines and check each one before execution.
	// This is intentionally conservative: if any line is denied, the entire
	// script is blocked (consistent with the POSIX per-command AST check).
	for _, rawLine := range splitPowerShellStatements(script) {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := tokenizePowerShellLine(line)
		if len(tokens) == 0 {
			continue
		}
		if err := bapGuard(tokens, ws, sess, client, timeout); err != nil {
			return err
		}
	}

	// ── Execute via pwsh ──────────────────────────────────────────────────
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"-NoProfile", "-NonInteractive", "-Command", script}
	cmd := exec.CommandContext(subCtx, psExe, args...)
	cmd.Dir = ws
	cmd.Env = envList
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout

	// Capture stderr so we can surface it cleanly
	var stderrBuf bytes.Buffer
	if opts.Stderr != nil {
		cmd.Stderr = io.MultiWriter(opts.Stderr, &stderrBuf)
	} else {
		cmd.Stderr = &stderrBuf
	}

	if err := cmd.Run(); err != nil {
		if stderrBuf.Len() > 0 {
			return fmt.Errorf("bapsh[pwsh]: %w\nstderr: %s", err, strings.TrimSpace(stderrBuf.String()))
		}
		return fmt.Errorf("bapsh[pwsh]: %w", err)
	}
	return nil
}

// splitPowerShellStatements splits a PowerShell script into individual
// statements for pre-flight BAP checking.  It splits on newlines and
// semicolons while respecting quoted strings and here-strings.
func splitPowerShellStatements(script string) []string {
	var stmts []string
	var cur strings.Builder
	inSingle := false
	inDouble := false

	for i := 0; i < len(script); i++ {
		ch := script[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteByte(ch)
		case ch == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteByte(ch)
		case (ch == '\n' || ch == ';') && !inSingle && !inDouble:
			stmts = append(stmts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		stmts = append(stmts, cur.String())
	}
	return stmts
}

// tokenizePowerShellLine splits a single PowerShell statement into tokens,
// stripping simple quoting so that bapGuard receives the logical command name
// and arguments (e.g. ["Copy-Item", "src.txt", "dst.txt"]).
func tokenizePowerShellLine(line string) []string {
	// Strip pipeline continuation — take only the first command segment
	// so that "Get-Content foo.txt | Select-String bar" is classified as
	// ["Get-Content", "foo.txt"] (the read side that determines grant need).
	if idx := strings.Index(line, " | "); idx >= 0 {
		line = line[:idx]
	}
	var tokens []string
	var cur strings.Builder
	inQ := false
	qCh := byte(0)

	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case !inQ && (ch == '\'' || ch == '"'):
			inQ = true
			qCh = ch
		case inQ && ch == qCh:
			inQ = false
		case !inQ && (ch == ' ' || ch == '\t'):
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}
