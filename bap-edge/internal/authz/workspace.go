package authz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// GetWorkspaceRoot resolves the canonical absolute path of the project workspace root.
// Precedence:
// 1. BAP_WORKSPACE_ROOT environment variable
// 2. LTD_WORKSPACE_ROOT environment variable
// 3. Git repository root (.git directory in current or ancestor path)
// 4. Current working directory (CWD)
func GetWorkspaceRoot() string {
	if root := os.Getenv("BAP_WORKSPACE_ROOT"); root != "" {
		if abs, err := filepath.Abs(root); err == nil {
			return filepath.Clean(abs)
		}
	}
	if root := os.Getenv("LTD_WORKSPACE_ROOT"); root != "" {
		if abs, err := filepath.Abs(root); err == nil {
			return filepath.Clean(abs)
		}
	}

	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for {
			if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
				return filepath.Clean(dir)
			}
			parent := filepath.Dir(dir)
			if parent == dir || parent == "" {
				break
			}
			dir = parent
		}
		return filepath.Clean(cwd)
	}

	return "."
}

// IsPathOutsideWorkspace checks whether targetPath (relative or absolute) resolves
// outside workspaceRoot.
// Permitted (Inside): child submodules, subdirectories, files within workspaceRoot.
// Forbidden (Outside): paths resolving above workspaceRoot, or absolute paths outside it.
func IsPathOutsideWorkspace(workspaceRoot, targetPath string) bool {
	if workspaceRoot == "" || targetPath == "" {
		return false
	}
	cleanRoot := filepath.Clean(workspaceRoot)

	// Explicit root reference (e.g. "/" or "/*" or "\*") targets the filesystem or drive root,
	// which is strictly outside any project workspace boundary.
	normTarget := strings.ReplaceAll(targetPath, "\\", "/")
	if normTarget == "/" || normTarget == "/*" || normTarget == "/." {
		return true
	}

	var absTarget string
	if filepath.IsAbs(targetPath) {
		absTarget = filepath.Clean(targetPath)
	} else if strings.HasPrefix(normTarget, "/") {
		vol := filepath.VolumeName(cleanRoot)
		absTarget = filepath.Clean(vol + filepath.FromSlash(normTarget))
	} else {
		absTarget = filepath.Clean(filepath.Join(cleanRoot, targetPath))
	}

	rel, err := filepath.Rel(cleanRoot, absTarget)
	if err != nil {
		// On Windows, if drives differ (e.g. C: vs D:), Rel returns an error.
		// That is strictly outside the workspace boundary.
		return true
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.HasPrefix(rel, "../") {
		return true
	}

	return false
}

// CheckCommandWorkspaceEscape inspects a shell command string for directory traversal
// or path references that escape the given workspaceRoot.
// It tracks sequential directory changes (`cd`, `pushd`) and inspects file path arguments.
func CheckCommandWorkspaceEscape(workspaceRoot, fullCommand string) bool {
	if workspaceRoot == "" || fullCommand == "" {
		return false
	}
	cleanRoot := filepath.Clean(workspaceRoot)
	currentDir := cleanRoot

	// Split compound commands by chaining operators: &&, ||, ;, |
	// Replace operators with a uniform delimiter
	cmdUnified := fullCommand
	for _, sep := range []string{"&&", "||", ";", "|", "&"} {
		cmdUnified = strings.ReplaceAll(cmdUnified, sep, "\n")
	}

	lines := strings.Split(cmdUnified, "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		tokens := tokenizeCommand(line)
		if len(tokens) == 0 {
			continue
		}

		first := strings.ToLower(tokens[0])

		// 1. Directory navigation: cd, chdir, pushd
		if first == "cd" || first == "chdir" || first == "pushd" {
			if len(tokens) >= 2 {
				cdTarget := tokens[1]
				// Strip quotes
				cdTarget = strings.Trim(cdTarget, "\"'")
				// Ignore flags like /d on Windows cd /d <target>
				if strings.EqualFold(cdTarget, "/d") && len(tokens) >= 3 {
					cdTarget = strings.Trim(tokens[2], "\"'")
				}

				if cdTarget == "" || cdTarget == "~" {
					// Navigating to user home directory from workspace is an escape
					return true
				}

				var nextAbs string
				if filepath.IsAbs(cdTarget) {
					nextAbs = filepath.Clean(cdTarget)
				} else {
					nextAbs = filepath.Clean(filepath.Join(currentDir, cdTarget))
				}

				if IsPathOutsideWorkspace(cleanRoot, nextAbs) {
					return true
				}
				// Advance currentDir within the workspace (e.g. into child-project)
				currentDir = nextAbs
			}
			continue
		}

		// 2. Inspect arguments for paths referencing .. or absolute paths outside workspace
		for i, tok := range tokens {
			if i == 0 {
				// Skip first token if it's the executable itself unless it starts with ..
				if !strings.HasPrefix(tok, "..") {
					continue
				}
			}

			tokVal := strings.Trim(tok, "\"'")
			if IsStandardDevicePath(tokVal) {
				continue
			}
			if strings.Contains(tokVal, ">") {
				parts := strings.Split(tokVal, ">")
				if len(parts) > 1 && IsStandardDevicePath(parts[len(parts)-1]) {
					continue
				}
			}

			// Check for --flag=path syntax
			if idx := strings.Index(tokVal, "="); idx != -1 && strings.HasPrefix(tokVal, "-") {
				tokVal = tokVal[idx+1:]
			}

			// Path contains traversal sequences
			if strings.Contains(tokVal, "..") {
				var absArg string
				if filepath.IsAbs(tokVal) {
					absArg = filepath.Clean(tokVal)
				} else {
					absArg = filepath.Clean(filepath.Join(currentDir, tokVal))
				}
				if IsPathOutsideWorkspace(cleanRoot, absArg) {
					return true
				}
			}

			// Absolute path check (Windows C:\... or POSIX /...)
			if isExplicitAbsolutePath(tokVal) {
				cleanAbs := filepath.Clean(tokVal)
				// Allow standard system build tools or temp dirs if explicitly configured,
				// but block project-level file inspection outside workspace
				if IsPathOutsideWorkspace(cleanRoot, cleanAbs) {
					// Check if it's not a known harmless system executable path
					if !isSystemBinaryPath(cleanAbs) {
						return true
					}
				}
			}
		}
	}

	return false
}

// IsStandardDevicePath returns true if target represents a standard stream or bitbucket pseudo-device
// (such as /dev/null, /dev/zero, /dev/stdout, /dev/stderr, nul, $null, 2>&1).
func IsStandardDevicePath(target string) bool {
	clean := strings.ToLower(strings.TrimSpace(target))
	clean = strings.Trim(clean, "\"'`")
	if strings.HasPrefix(clean, "&") || strings.Contains(clean, ">&") {
		return true
	}
	switch clean {
	case "/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/stdin",
		"nul", "nul:", "\\\\.\\nul", "$null", "none":
		return true
	}
	norm := filepath.ToSlash(clean)
	if norm == "/dev/null" || norm == "/dev/zero" || norm == "/dev/stdout" || norm == "/dev/stderr" || strings.HasSuffix(norm, "/nul") {
		return true
	}
	return false
}

// IsStrictTierMandated checks whether the Central Control Plane has commanded
// Tier 2 Strict Tool Enforcement for this workload.
// By default, Tier 1 (Standard Governance: Prompt-First Observability + Boundary Invariants)
// is active everywhere. Tier 2 is OFF by default unless explicitly commanded by Control Plane.
func IsStrictTierMandated() bool {
	// 1. Explicit environment overrides
	if tierEnv := strings.TrimSpace(os.Getenv("BAP_TIER")); tierEnv == "1" || strings.EqualFold(tierEnv, "standard") {
		return false
	} else if tierEnv == "2" || strings.EqualFold(tierEnv, "strict") {
		return true
	}
	if strictEnv := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_STRICT_TOOLS"))); strictEnv == "true" || strictEnv == "1" {
		return true
	}

	// 2. Query cached policy-state.json pushed by Central Control Plane
	candidates := []string{
		filepath.Join(".bap", "policy-state.json"),
		filepath.Join("..", ".bap", "policy-state.json"),
		"policy-state.json",
		"../policy-state.json",
		filepath.Join("bap-edge", "policy-state.json"),
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".bapstate", "policy", "policy-state.json"))
		candidates = append(candidates, filepath.Join(home, ".bap", "policy-state.json"))
	}

	for _, cand := range candidates {
		if data, err := os.ReadFile(cand); err == nil {
			var st struct {
				StrictToolEnforcement bool   `json:"strict_tool_enforcement"`
				EnforcementTier       string `json:"enforcement_tier"`
			}
			if json.Unmarshal(data, &st) == nil {
				if st.StrictToolEnforcement || strings.EqualFold(st.EnforcementTier, "tier_2_strict") || strings.EqualFold(st.EnforcementTier, "strict") {
					return true
				}
			}
		}
	}

	// Default: Tier 2 is ALWAYS OFF by default! Tier 1 Standard applies.
	return false
}

func isExplicitAbsolutePath(p string) bool {
	if IsStandardDevicePath(p) {
		return false
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true // Windows drive: C:\ or C:/
	}
	if strings.HasPrefix(p, "\\\\") || strings.HasPrefix(p, "//") {
		return true // UNC path
	}
	normP := strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(normP, "/") {
		// Bare root "/" ("\") or paths with subpaths "/dir/file" are absolute paths
		if normP == "/" || strings.Contains(normP[1:], "/") {
			return true
		}
		// Single-letter switch flags (e.g. /c, /d, /s, /b, /q, /y) on Windows are flags, not paths
		if len(normP) == 2 && strings.HasPrefix(p, "/") {
			return false
		}
		// Root-level dirs like /etc, /tmp, /var, /bin, /usr, /home, /opt, /dev
		lower := strings.ToLower(normP[1:])
		switch lower {
		case "etc", "tmp", "var", "home", "root", "bin", "usr", "opt", "mnt", "proc", "dev", "sys", "lib", "lib64", "srv", "windows", "program files", "users":
			return true
		}
		// On non-Windows OS, anything starting with / is an absolute path
		if runtime.GOOS != "windows" {
			return true
		}
	}
	return false
}

func isSystemBinaryPath(p string) bool {
	lower := strings.ToLower(filepath.ToSlash(p))
	systemPrefixes := []string{
		"c:/windows/",
		"c:/program files/",
		"c:/program files (x86)/",
		"/usr/bin/",
		"/bin/",
		"/usr/local/bin/",
	}
	for _, sp := range systemPrefixes {
		if strings.HasPrefix(lower, sp) && (strings.HasSuffix(lower, ".exe") || !strings.Contains(filepath.Base(lower), ".")) {
			return true
		}
	}
	return false
}

// tokenizeCommand parses a single command line into tokens, respecting quotes.
func tokenizeCommand(cmd string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	var quoteChar rune

	for _, r := range cmd {
		if inQuote {
			if r == quoteChar {
				inQuote = false
			}
			current.WriteRune(r)
		} else {
			if r == '"' || r == '\'' {
				inQuote = true
				quoteChar = r
				current.WriteRune(r)
			} else if r == ' ' || r == '\t' {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// TokenizeCommand parses a single command line into tokens, respecting quotes.
func TokenizeCommand(cmd string) []string {
	return tokenizeCommand(cmd)
}

// ResolveVariablePaths extracts variable assignments (e.g. $p = '...', $p = Join-Path ...)
// and returns a map of variable name -> resolved absolute or canonical path.
func ResolveVariablePaths(cmd, workspaceRoot string) map[string]string {
	vars := make(map[string]string)
	cleanRoot := filepath.Clean(workspaceRoot)

	unified := cmd
	for _, sep := range []string{"\n", "\r", ";"} {
		unified = strings.ReplaceAll(unified, sep, "\n")
	}
	for _, line := range strings.Split(unified, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "$") && !strings.Contains(trimmed, "=") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		varName := strings.TrimSpace(parts[0])
		rawVal := strings.TrimSpace(parts[1])
		if !strings.HasPrefix(varName, "$") {
			continue
		}
		val := strings.Trim(rawVal, "\"'` \t")
		if strings.Contains(rawVal, "Join-Path") || strings.Contains(rawVal, "Resolve-Path") || strings.Contains(rawVal, "..") {
			var baseDir string
			var childDir string
			tokens := strings.Fields(rawVal)
			for _, t := range tokens {
				cleanT := strings.Trim(t, "\"'`(),; \t")
				if idx := strings.Index(cleanT, ")"); idx != -1 {
					cleanT = cleanT[:idx]
				}
				if strings.Contains(cleanT, "..") || isExplicitAbsolutePath(cleanT) {
					baseDir = cleanT
				} else if cleanT != "" && !strings.Contains(cleanT, "Path") && !strings.Contains(cleanT, "Join") && !strings.Contains(cleanT, "Resolve") && !strings.HasPrefix(cleanT, "-") && !strings.HasPrefix(cleanT, "$") {
					childDir = cleanT
				}
			}
			if baseDir != "" {
				resolvedBase := ResolveCanonicalPath(baseDir, cleanRoot)
				if childDir != "" {
					val = filepath.Clean(filepath.Join(resolvedBase, childDir))
				} else {
					val = resolvedBase
				}
			}
		} else if isExplicitAbsolutePath(val) || strings.Contains(val, "..") || strings.Contains(val, string(filepath.Separator)) || strings.Contains(val, "/") {
			val = ResolveCanonicalPath(val, cleanRoot)
		}
		if val != "" {
			vars[varName] = val
		}
	}
	return vars
}

// FindEscapingTargets returns all canonical file paths in cmdArgs that escape workspaceRoot.
func FindEscapingTargets(workspaceRoot, cmdArgs string) []string {
	if workspaceRoot == "" || cmdArgs == "" {
		return nil
	}
	cleanRoot := filepath.Clean(workspaceRoot)
	varMap := ResolveVariablePaths(cmdArgs, workspaceRoot)

	expandedCmd := cmdArgs
	for vName, vVal := range varMap {
		expandedCmd = strings.ReplaceAll(expandedCmd, vName, vVal)
	}

	tokens := tokenizeCommand(expandedCmd)
	var targets []string
	for _, tok := range tokens {
		if isCommandFlag(tok) {
			continue
		}
		val := strings.Trim(tok, "\"'`")
		if idx := strings.Index(val, "="); idx != -1 && strings.HasPrefix(val, "-") {
			val = val[idx+1:]
		}
		if val == "" || IsStandardDevicePath(val) {
			continue
		}
		if strings.Contains(val, ">") {
			parts := strings.Split(val, ">")
			if len(parts) > 1 && IsStandardDevicePath(parts[len(parts)-1]) {
				continue
			}
		}
		canon := ResolveCanonicalPath(val, cleanRoot)
		if IsPathOutsideWorkspaceCanonical(cleanRoot, canon) {
			targets = append(targets, canon)
		}
	}
	return targets
}

// IsFilesystemRootTarget returns true if target refers directly to a filesystem or drive root
// (e.g. "/", "\", "/*", "\*", "C:\", "C:/").
func IsFilesystemRootTarget(target string) bool {
	trimmed := strings.TrimSpace(strings.Trim(target, "\"'`"))
	if trimmed == "" {
		return false
	}
	norm := strings.ReplaceAll(trimmed, "\\", "/")
	if norm == "/" || norm == "/*" || norm == "/." || norm == "//" {
		return true
	}
	// Drive root: "C:/", "C:", "C:/*"
	if len(norm) >= 2 && norm[1] == ':' && ((norm[0] >= 'a' && norm[0] <= 'z') || (norm[0] >= 'A' && norm[0] <= 'Z')) {
		rest := strings.TrimPrefix(norm[2:], "/")
		if rest == "" || rest == "*" || rest == "." {
			return true
		}
	}
	return false
}

// HasFilesystemRootEscape checks whether any non-flag token in cmdTargets is an explicit
// filesystem or drive root path outside workspaceRoot.
func HasFilesystemRootEscape(workspaceRoot, fullCommand string) bool {
	if fullCommand == "" {
		return false
	}
	cleanRoot := filepath.Clean(workspaceRoot)
	for _, tok := range tokenizeCommand(fullCommand) {
		if isCommandFlag(tok) {
			continue
		}
		val := strings.Trim(tok, "\"'`")
		if val == "" || IsStandardDevicePath(val) {
			continue
		}
		if IsFilesystemRootTarget(val) {
			if cleanRoot == "" || IsPathOutsideWorkspaceCanonical(cleanRoot, val) {
				return true
			}
		}
	}
	return false
}
