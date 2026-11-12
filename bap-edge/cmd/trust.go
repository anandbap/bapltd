package cmd

import (
	"bap-edge/internal/authz"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RunTrust handles 'bapedge trust <path> [--project | --global | --session]'.
func RunTrust(args []string) error {
	// BAP-934: trust is a human decision. An agent must never be able to widen its own boundary by
	// running `bapedge trust`. The gate for agents is the hook/broker (agent tool calls that invoke
	// trust are refused there, and the trust files are write-protected); this process-level check is
	// defense in depth and keys ONLY on BAP_IN_BROKER, which the broker sets for sandboxed children.
	// It deliberately does NOT sniff other environment variables (LTD_SOURCE, BAP_SESSION_ID, ...):
	// a developer's shell or CI job can legitimately carry them, and a developer must always be able
	// to run `bap trust`.
	if strings.TrimSpace(os.Getenv("BAP_IN_BROKER")) != "" {
		return fmt.Errorf("%w: `bapedge trust` is a human-operator action and cannot run inside an agent session; run it in your own terminal", authz.ErrHighRiskApprovalRequired)
	}
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	projectFlag := fs.Bool("project", false, "Grant permission for current project workspace (default)")
	globalFlag := fs.Bool("global", false, "Grant permission globally across all projects on this workstation")
	sessionFlag := fs.Bool("session", false, "Grant permission only for current active session")
	sessionIDFlag := fs.String("session-id", os.Getenv("BAP_SESSION_ID"), "Target session ID (for session scope)")
	actionsFlag := fs.String("actions", "write,delete", "Comma-separated list of allowed actions (write, delete, all)")
	jsonFlag := fs.Bool("json", false, "Output result in JSON format")

	var flagArgs []string
	var posArgs []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
		} else {
			posArgs = append(posArgs, a)
		}
	}
	reordered := append(flagArgs, posArgs...)

	if err := fs.Parse(reordered); err != nil {
		return err
	}

	remaining := fs.Args()
	if len(remaining) == 0 || remaining[0] == "list" {
		return RunPermissions(args)
	}

	targetPath := remaining[0]
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		absPath = filepath.Clean(targetPath)
	}

	scope := "project"
	if *globalFlag {
		scope = "global"
	} else if *sessionFlag {
		scope = "session"
	} else if *projectFlag {
		scope = "project"
	}

	actionsList := strings.Split(*actionsFlag, ",")
	for i, a := range actionsList {
		actionsList[i] = strings.ToLower(strings.TrimSpace(a))
	}

	workspaceRoot := authz.GetWorkspaceRoot()
	err = authz.GrantPermission(workspaceRoot, *sessionIDFlag, absPath, scope, actionsList)
	if err != nil {
		return fmt.Errorf("failed to grant permission: %w", err)
	}
	if scope == "session" && *sessionIDFlag != "default" && *sessionIDFlag != "" {
		_ = authz.GrantPermission(workspaceRoot, "default", absPath, scope, actionsList)
	}

	if *jsonFlag {
		fmt.Printf(`{"status":"ok","path":%q,"scope":%q,"actions":%v}`+"\n", absPath, scope, actionsList)
		return nil
	}

	fmt.Println("================================================================================")
	fmt.Println(" [BAP ZERO-TRUST] CROSS-FOLDER MUTATION PERMISSION GRANTED")
	fmt.Println("================================================================================")
	fmt.Printf(" Target Path : %s\n", absPath)
	fmt.Printf(" Scope       : %s\n", strings.ToUpper(scope))
	fmt.Printf(" Actions     : %s\n", strings.Join(actionsList, ", "))
	fmt.Println(" Read access : implied (the agent can read here under a normal ZSP grant; credential files are never exposed)")
	fmt.Printf(" Workspace   : %s\n", workspaceRoot)
	if scope == "project" {
		fmt.Printf(" Config File : %s\n", authz.GetProjectPermissionsPath(workspaceRoot))
	} else if scope == "global" {
		fmt.Printf(" Config File : %s\n", authz.GetGlobalPermissionsPath())
	}
	fmt.Println("================================================================================")
	return nil
}

// RunUntrust handles 'bapedge untrust <path> [--project | --global | --session]'.
func RunUntrust(args []string) error {
	if strings.TrimSpace(os.Getenv("BAP_IN_BROKER")) != "" {
		return fmt.Errorf("%w: `bapedge untrust` is a human-operator action and cannot run inside an agent session", authz.ErrHighRiskApprovalRequired)
	}
	fs := flag.NewFlagSet("untrust", flag.ContinueOnError)
	projectFlag := fs.Bool("project", false, "Revoke permission from current project workspace (default)")
	globalFlag := fs.Bool("global", false, "Revoke permission globally")
	sessionFlag := fs.Bool("session", false, "Revoke permission from session")
	sessionIDFlag := fs.String("session-id", os.Getenv("BAP_SESSION_ID"), "Target session ID")

	var flagArgs []string
	var posArgs []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
		} else {
			posArgs = append(posArgs, a)
		}
	}
	reordered := append(flagArgs, posArgs...)

	if err := fs.Parse(reordered); err != nil {
		return err
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return fmt.Errorf("usage: bapedge untrust <path> [--project | --global | --session]")
	}

	targetPath := remaining[0]
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		absPath = filepath.Clean(targetPath)
	}

	scope := "project"
	if *globalFlag {
		scope = "global"
	} else if *sessionFlag {
		scope = "session"
	} else if *projectFlag {
		scope = "project"
	}

	workspaceRoot := authz.GetWorkspaceRoot()
	err = authz.RevokePermission(workspaceRoot, *sessionIDFlag, absPath, scope)
	if err != nil {
		return fmt.Errorf("failed to revoke permission: %w", err)
	}

	fmt.Printf("[+] Revoked %s cross-folder permission for: %s\n", scope, absPath)
	return nil
}

// RunPermissions handles 'bapedge permissions' or 'bapedge trust list'.
func RunPermissions(args []string) error {
	workspaceRoot := authz.GetWorkspaceRoot()
	sessionID := os.Getenv("BAP_SESSION_ID")

	all := authz.ListAllPermissions(workspaceRoot, sessionID)

	fmt.Println("================================================================================")
	fmt.Println(" BAP ZERO-TRUST AUTHORIZED CROSS-FOLDER PERMISSIONS")
	fmt.Println("================================================================================")
	if len(all) == 0 {
		fmt.Println(" No cross-folder permissions granted. All external mutations are isolated.")
		fmt.Println(" To authorize a sibling directory, run: bapedge trust <path> [--project|--global]")
		fmt.Println("================================================================================")
		return nil
	}

	for _, p := range all {
		fmt.Printf(" [%s] %s\n", strings.ToUpper(p.Scope), p.Path)
		fmt.Printf("    Actions : %s\n", strings.Join(p.Actions, ", "))
		fmt.Printf("    Granted : %s\n", p.GrantedAt.Format("2006-01-02 15:04:05 UTC"))
	}
	fmt.Println("================================================================================")
	return nil
}
