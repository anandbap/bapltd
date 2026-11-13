package authz

import (
	"os"
	"strings"
)

// ReadExemptProvider reports the control-plane-managed zsp_read_exempt setting for this
// machine from the verified, signed policy state. It is registered by the cmd package (the
// policy store imports authz, so authz cannot import it). Nil means "no managed setting".
var ReadExemptProvider func() bool

// readOnlyInspectionTools are native agent tools that only read or search files.
var readOnlyInspectionTools = map[string]bool{
	"read": true, "view": true, "read_file": true, "view_file": true, "show_file": true,
	"get_file": true, "glob": true, "grep": true, "ls": true, "dir": true, "list": true,
	"list_dir": true, "list_directory": true, "list_files": true, "search": true,
	"search_code": true, "search_files": true, "find": true, "find_files": true,
}

// isLocalReadAction reports canonical effect actions that only read local files or inspect
// repository state. git:branch is deliberately absent (it also creates and deletes branches).
func isLocalReadAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "fs:read", "fs:file:read", "fs:dir:read", "git:inspect:read",
		"git:status", "git:log", "git:diff", "git:show":
		return true
	}
	return false
}

// IsLocalReadOnlyCommand reports whether a shell command's EVERY effect is a plain local read
// inside the workspace, so it needs no task grant (the same reasoning as Read/Glob/Grep). It is
// conservative on purpose: any output redirection, any non-read effect, any target outside the
// workspace or in a credential store makes it false, and a mixed command needs a grant covering
// all of its effects.
func IsLocalReadOnlyCommand(command, executable, args, workspaceRoot string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("BAP_ZSP_STRICT_READS"))) {
	case "1", "true", "on", "yes":
		return false
	}
	if ReadExemptProvider != nil && !ReadExemptProvider() {
		return false
	}
	if strings.TrimSpace(command) == "" || strings.Contains(command, ">") {
		return false
	}
	checks := ResolveZSPCommandChecks(command, executable, args, "", "", workspaceRoot)
	if len(checks) == 0 {
		return false
	}
	for _, c := range checks {
		if c.EscapesWorkspace || !isLocalReadAction(c.Action) {
			return false
		}
		res := strings.TrimPrefix(c.CanonicalResource, "file://")
		if isCredentialStorePath(res) || IsFilesystemRootTarget(res) {
			return false
		}
	}
	return true
}

// IsWorkspaceReadOnlyToolCall reports whether a native tool call is plain read-only
// inspection of the project (Read, Glob, Grep, directory listing, ...), so a developer's
// agent can review their own code without first minting a task grant.
//
// It is deliberately narrow. It is false (grant or override still required) for:
//   - any mutating tool (Edit, Write, delete, patch, shell commands);
//   - targets outside the workspace, including filesystem/drive roots;
//   - credential stores (.env, .aws, .ssh, private keys), which stay hard-denied.
//
// Set BAP_ZSP_STRICT_READS=1 to require grants for reads as well.
func IsWorkspaceReadOnlyToolCall(toolName, target, workspaceRoot string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("BAP_ZSP_STRICT_READS"))) {
	case "1", "true", "on", "yes":
		return false
	}
	// The control plane owns this setting (signed, per asset). If it says reads need grants,
	// or the signed rules cannot be verified, nothing is exempt.
	if ReadExemptProvider != nil && !ReadExemptProvider() {
		return false
	}
	if !readOnlyInspectionTools[strings.ToLower(strings.TrimSpace(toolName))] {
		return false
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return true // search/list tools default to the workspace
	}
	canonical := ResolveCanonicalPath(target, workspaceRoot)
	if canonical == "" {
		canonical = target
	}
	if IsFilesystemRootTarget(target) || IsFilesystemRootTarget(canonical) {
		return false
	}
	if isCredentialStorePath(canonical) || isCredentialStorePath(target) {
		return false
	}
	return !IsPathOutsideWorkspaceCanonical(workspaceRoot, canonical)
}
