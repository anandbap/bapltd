package authz

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// BAP authority state (ZSP-REVIEW-01 hardening).
//
// The ZSP state directory holds the material that DECIDES what an agent may do: the PEP signing
// secret (pepper.key), the signed auto-approve window (autoapprove.json), pending human-approval
// requests, minted grants and native-invocation decisions. An agent that can read the secret can
// forge any signature; one that can write approvals/ or autoapprove.json can approve itself.
//
// BAP's own code reads and writes this state through Go APIs, never through the path screens in this
// package, so treating the whole subtree as a protected credential store costs the product nothing:
// `bapedge zsp authorize|status|grants|approvals` keep working because the agent never names a path.
// What it removes is the agent's ability to NAME these paths through a native Read/Grep/Glob tool or
// a shell command, which is the same class of refusal already applied to .env, .ssh and .aws.

// authorityBaseNames are file names that only ever hold BAP authority material.
var authorityBaseNames = map[string]bool{
	"pepper.key":       true,
	"autoapprove.json": true,
}

// authorityDirMarkers identify the default state locations without consulting the filesystem
// (state.Dir() creates directories and runs migrations, which a path screen must never do).
var authorityDirMarkers = []string{"/.bapstate/zsp/", "/bapstate/zsp/"}

func normalizeAuthorityPath(p string) string {
	n := strings.TrimSpace(p)
	n = strings.Trim(n, "\"'`")
	if n == "" {
		return ""
	}
	n = strings.ReplaceAll(n, "\\", "/")
	// NTFS alternate data streams and trailing dots/spaces name the same file.
	if i := strings.Index(n, "::"); i >= 0 {
		n = n[:i]
	}
	n = strings.TrimRight(n, ". ")
	// Drive-relative or percent/env-style prefixes are left intact; markers and base names still match.
	return strings.ToLower(path.Clean(n))
}

func authorityDirs() []string {
	var dirs []string
	if d := strings.TrimSpace(os.Getenv("BAP_ZSP_DIR")); d != "" {
		dirs = append(dirs, d)
	}
	if d := strings.TrimSpace(os.Getenv("BAP_STATE_DIR")); d != "" {
		dirs = append(dirs, filepath.Join(d, "zsp"))
	}
	out := dirs[:0]
	for _, d := range dirs {
		n := normalizeAuthorityPath(d)
		// Never treat a filesystem root or the user's home as "the authority directory".
		if n == "" || n == "." || n == "/" || isOverrideExcludedPath(d) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// IsBAPAuthorityPath reports whether p names BAP's own authority state (signing key, auto-approve
// window, approval requests, grants, native decisions). It performs no filesystem access.
func IsBAPAuthorityPath(p string) bool {
	norm := normalizeAuthorityPath(p)
	if norm == "" {
		return false
	}
	if authorityBaseNames[path.Base(norm)] {
		return true
	}
	withSlash := "/" + strings.TrimPrefix(norm, "/") + "/"
	for _, m := range authorityDirMarkers {
		if strings.Contains(withSlash, m) {
			return true
		}
	}
	for _, d := range authorityDirs() {
		if norm == d || strings.HasPrefix(norm, d+"/") {
			return true
		}
	}
	return false
}
