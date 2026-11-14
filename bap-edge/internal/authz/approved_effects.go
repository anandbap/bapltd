package authz

import (
	"os"
	"regexp"
	"strings"
)

// ApprovedEffectsProvider returns the effects an administrator approved for THIS machine, taken
// from the verified, signed policy state (set by the cmd package, like ReadExemptProvider). Nil or
// an unverifiable state means nothing is approved.
var ApprovedEffectsProvider func() []string

var effectShape = regexp.MustCompile(`^[a-z0-9][a-z0-9:_\-.]{1,62}$`)

var neverApprovableParts = []string{
	":delete", ":push", ":install", ":publish", ":deploy", ":upload", ":exfil", ":sudo", ":admin", ":kill",
}
var neverApprovablePrefixes = []string{"net:", "http", "db:", "cli:", "sys:", "iam:", "secret", "cred", "system:"}
var approvablePrefixes = []string{"dev:", "fs:file:write", "fs:file:edit", "git:commit", "git:branch:write", "git:add", "git:stash"}

// ApprovableEffect reports whether a canonical action may ever be relaxed by an administrator
// approval. It mirrors bap-controlplane/internal/policy.ApprovableEffect; the edge re-checks it so
// a control plane (or a forged list) can never widen BAP beyond the local development loop.
func ApprovableEffect(action string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	if !effectShape.MatchString(a) {
		return false
	}
	for _, p := range neverApprovablePrefixes {
		if strings.HasPrefix(a, p) {
			return false
		}
	}
	for _, part := range neverApprovableParts {
		if strings.Contains(a, part) {
			return false
		}
	}
	for _, p := range approvablePrefixes {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	return false
}

func approvedEffectSet() map[string]bool {
	if ApprovedEffectsProvider == nil {
		return nil
	}
	list := ApprovedEffectsProvider()
	if len(list) == 0 {
		return nil
	}
	set := make(map[string]bool, len(list))
	for _, e := range list {
		e = strings.ToLower(strings.TrimSpace(e))
		if ApprovableEffect(e) {
			set[e] = true
		}
	}
	return set
}

func strictReadsForced() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("BAP_ZSP_STRICT_READS"))) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// IsApprovedLocalCommand reports whether EVERY effect of a shell command is either a plain local read
// or an effect the administrator approved for this machine, all inside the workspace. Credential
// stores, filesystem roots and anything that escapes the workspace are never covered, and output
// redirection still needs a grant. Cedar invariants are evaluated separately and are not relaxed.
func IsApprovedLocalCommand(command, executable, args, workspaceRoot string) bool {
	if strictReadsForced() {
		return false
	}
	approved := approvedEffectSet()
	if len(approved) == 0 || strings.TrimSpace(command) == "" || strings.Contains(command, ">") {
		return false
	}
	checks := ResolveZSPCommandChecks(command, executable, args, "", "", workspaceRoot)
	if len(checks) == 0 {
		return false
	}
	usedApproval := false
	for _, c := range checks {
		if c.EscapesWorkspace {
			return false
		}
		res := strings.TrimPrefix(c.CanonicalResource, "file://")
		if isCredentialStorePath(res) || IsFilesystemRootTarget(res) {
			return false
		}
		act := strings.ToLower(strings.TrimSpace(c.Action))
		switch {
		case approved[act]:
			usedApproval = true
		case isLocalReadAction(act) && (ReadExemptProvider == nil || ReadExemptProvider()):
			// plain read, exempt under the machine's read-exemption setting
		default:
			return false
		}
	}
	return usedApproval
}

// IsApprovedToolCall is the native-tool counterpart (Write, Edit, ...): the call's resolved effect
// must be approved and its target inside the workspace and not a credential store or root.
func IsApprovedToolCall(toolName, target, workspaceRoot string) bool {
	if strictReadsForced() || strings.TrimSpace(toolName) == "" {
		return false
	}
	approved := approvedEffectSet()
	if len(approved) == 0 {
		return false
	}
	checks := ResolveZSPCommandChecks("", "", "", toolName, target, workspaceRoot)
	if len(checks) == 0 {
		return false
	}
	for _, c := range checks {
		if c.EscapesWorkspace || !approved[strings.ToLower(strings.TrimSpace(c.Action))] {
			return false
		}
		res := strings.TrimPrefix(strings.TrimPrefix(c.CanonicalResource, "file://"), "dir://")
		if isCredentialStorePath(res) || IsFilesystemRootTarget(res) || isCredentialStorePath(target) {
			return false
		}
	}
	return true
}
