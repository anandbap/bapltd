package authz

import (
	"os"
	"path/filepath"
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

func isExplicitAbsolutePath(p string) bool {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true // Windows drive: C:\ or C:/
	}
	if strings.HasPrefix(p, "\\\\") || strings.HasPrefix(p, "//") {
		return true // UNC path
	}
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "/c") && !strings.HasPrefix(p, "/d") && !strings.HasPrefix(p, "/s") && !strings.HasPrefix(p, "/b") {
		// POSIX absolute path
		return true
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
