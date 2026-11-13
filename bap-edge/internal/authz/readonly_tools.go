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
