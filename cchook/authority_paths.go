package main

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Mirror of bap-edge/internal/authz/authority_paths.go (ZSP-REVIEW-01 hardening). The hook binary
// cannot import bap-edge internals, so the same rules are repeated here and share golden vectors in
// the tests. BAP's authority state (signing key, auto-approve window, approvals, grants) must never be
// nameable by an agent tool call. No filesystem access is performed.

var authorityBaseNames = map[string]bool{"pepper.key": true, "autoapprove.json": true}

var authorityDirMarkers = []string{"/.bapstate/zsp/", "/bapstate/zsp/"}

func normalizeAuthorityPath(p string) string {
	n := strings.Trim(strings.TrimSpace(p), "\"'`")
	if n == "" {
		return ""
	}
	n = strings.ReplaceAll(n, "\\", "/")
	if i := strings.Index(n, "::"); i >= 0 {
		n = n[:i]
	}
	n = strings.TrimRight(n, ". ")
	return strings.ToLower(path.Clean(n))
}

func authorityDirs() []string {
	var raw []string
	if d := strings.TrimSpace(os.Getenv("BAP_ZSP_DIR")); d != "" {
		raw = append(raw, d)
	}
	if d := strings.TrimSpace(os.Getenv("BAP_STATE_DIR")); d != "" {
		raw = append(raw, filepath.Join(d, "zsp"))
	}
	var out []string
	for _, d := range raw {
		n := normalizeAuthorityPath(d)
		if n == "" || n == "." || n == "/" || strings.Count(strings.Trim(n, "/"), "/") < 1 {
			continue
		}
		out = append(out, n)
	}
	return out
}

func isBAPAuthorityPath(p string) bool {
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
