package authz

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Prescriptive guidance (BAP-934). When an agent reaches for a folder outside the workspace, the
// refusal must say exactly what happens next and who does it: the DEVELOPER authorizes the folder
// with `bap trust` in their own terminal. The agent is told to stop and relay the command; it is
// never told to run it (and cannot: the command and the trust files are agent-proof).

// OutOfWorkspaceTarget returns the first outside-workspace filesystem target among checks.
func OutOfWorkspaceTarget(checks []ZSPActionCheck) (target string, action string, ok bool) {
	for _, c := range checks {
		if !c.EscapesWorkspace {
			continue
		}
		res := c.CanonicalResource
		switch {
		case strings.HasPrefix(res, "file://"):
			return filepath.FromSlash(strings.TrimPrefix(res, "file://")), c.Action, true
		case strings.HasPrefix(res, "dir://"):
			return filepath.FromSlash(strings.TrimPrefix(res, "dir://")), c.Action, true
		}
	}
	return "", "", false
}

// CrossFolderAccessType returns "write" for commands that redirect output into a file (a redirect is a
// write even when the executable, such as echo, is classified as a read), else the classified type.
func CrossFolderAccessType(actionType, fullCommand string) string {
	if strings.Contains(fullCommand, ">") {
		return "write"
	}
	if actionType == "" {
		return "read"
	}
	return actionType
}

// trustFolderFor picks the folder a developer should trust for a target: the directory itself, or the
// parent directory of a file.
func trustFolderFor(target string) string {
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		return target
	}
	if filepath.Ext(target) == "" && !strings.ContainsAny(filepath.Base(target), ".") {
		// Looks like a directory that does not exist yet.
		return target
	}
	return filepath.Dir(target)
}

// FormatOutOfWorkspaceSuggestion tells the agent to stop and the developer exactly what to run.
func FormatOutOfWorkspaceSuggestion(target, action, workspaceRoot string) string {
	folder := trustFolderFor(target)
	if err := ValidateTrustTarget(folder); err != nil {
		return fmt.Sprintf(
			"BAP BOUNDARY: \"%s\" is outside the workspace (%s) and cannot be trusted: %v. "+
				"AGENT: stop and tell the developer. The developer can copy the file(s) you need into the workspace, or trust a specific, narrower folder with `bap trust \"<folder>\"` in their own terminal.",
			target, workspaceRoot, err)
	}
	access := "read"
	if t := trustActionForZSP(action); t != "read" {
		access = t + " (and read)"
	}
	return fmt.Sprintf(
		"BAP BOUNDARY: \"%s\" is outside the workspace (%s) and needs %s access. BAP never lets an agent widen its own boundary.\n"+
			"DEVELOPER ACTION REQUIRED: run ONE of these in your own terminal (not through the agent), then ask the agent to retry:\n"+
			"    bap trust \"%s\" --project     # this project only\n"+
			"    bap trust \"%s\" --session     # this session only\n"+
			"    bap trust \"%s\" --global      # every project on this workstation\n"+
			"A trusted folder is readable under a normal task grant; writes and deletes also need the matching trust action (default: write,delete). Credential files such as .env, .ssh and .aws stay blocked inside trusted folders.\n"+
			"AGENT: do not run `bap trust` and do not edit .bap/ files (both are blocked). Stop, relay the command above to the developer, and wait. If the file is needed only once, the developer can instead copy it into the workspace.",
		target, workspaceRoot, access, folder, folder, folder)
}

// ZSPDenialSuggestion chooses the right remediation text for a ZSP refusal.
func ZSPDenialSuggestion(err error, principal, sessionID, goal, actions string, checks []ZSPActionCheck, workspaceRoot string) string {
	if errors.Is(err, ErrResourceNotGranted) {
		if target, action, ok := OutOfWorkspaceTarget(checks); ok {
			return FormatOutOfWorkspaceSuggestion(target, action, workspaceRoot)
		}
	}
	return FormatZSPAgentSuggestion(principal, sessionID, goal, actions, len(checks))
}
