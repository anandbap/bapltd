package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/internal/bapsh"
)

// RunBapsh executes a command or script within the BAP restricted Go AST shell.
//
// Shell selection (--shell-hint flag):
//
//	auto        (default) auto-detect from shebang, env, and script content
//	bash        POSIX mode via mvdan.cc/sh/v3 (bash/sh/zsh-compatible)
//	sh          same as bash
//	zsh         same as bash (mvdan.cc/sh/v3 covers common zsh)
//	pwsh        PowerShell mode — delegates to pwsh/powershell.exe
//	powershell  same as pwsh
//	cmd         POSIX mode; Windows POSIX-alias shim handles cmd.exe built-ins
//
// Agents should pass --shell-hint explicitly rather than relying on auto-detection:
//
//	bapedge bapsh -c "Get-ChildItem -Recurse" --shell-hint pwsh
//	bapedge bapsh -c "ls -al | grep go"      --shell-hint bash
func RunBapsh(args []string) error {
	fs := flag.NewFlagSet("bapsh", flag.ContinueOnError)
	cFlag := fs.String("c", "", "Command string to execute in bapsh")
	timeoutFlag := fs.Duration("timeout", 5*time.Minute, "Execution timeout")
	sessionFlag := fs.String("session-id", os.Getenv("BAP_SESSION_ID"), "Active session ID")
	sourceFlag := fs.String("source", os.Getenv("LTD_SOURCE"), "Agent source identity")
	wsFlag := fs.String("workspace", "", "Workspace root")
	shellHintFlag := fs.String("shell-hint", os.Getenv("BAP_SHELL_HINT"), "Shell engine hint: auto, bash, sh, zsh, pwsh, powershell, cmd")

	if err := fs.Parse(args); err != nil {
		return err
	}

	script := *cFlag
	remaining := fs.Args()
	if script == "" && len(remaining) > 0 {
		script = strings.Join(remaining, " ")
	}
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("no command provided to bapsh. Usage: bapedge bapsh -c \"<command>\"")
	}

	sess := *sessionFlag
	if sess == "" {
		sess = "sess-bapsh-interactive"
	}

	source := *sourceFlag
	if source == "" {
		source = "agent"
	}

	ws := *wsFlag
	if ws == "" {
		ws = authz.GetWorkspaceRoot()
	}

	opts := bapsh.Options{
		Mode:          bapsh.ParseShellHint(*shellHintFlag),
		SessionID:     sess,
		ClientType:    source,
		WorkspaceRoot: ws,
		Stdin:         os.Stdin,
		Stdout:        os.Stdout,
		Stderr:        os.Stderr,
		Timeout:       *timeoutFlag,
	}

	return bapsh.Run(context.Background(), script, opts)
}
