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
func RunBapsh(args []string) error {
	fs := flag.NewFlagSet("bapsh", flag.ContinueOnError)
	cFlag := fs.String("c", "", "Command string to execute in bapsh")
	timeoutFlag := fs.Duration("timeout", 5*time.Minute, "Execution timeout")
	sessionFlag := fs.String("session-id", os.Getenv("BAP_SESSION_ID"), "Active session ID")
	sourceFlag := fs.String("source", os.Getenv("LTD_SOURCE"), "Agent source identity")
	wsFlag := fs.String("workspace", "", "Workspace root")

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
