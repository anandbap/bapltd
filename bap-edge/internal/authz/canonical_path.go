package authz

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ResolveCanonicalPath resolves a target file path to its canonical, real filesystem destination:
// 1. Expands tilde ~ to the user's home directory.
// 2. Joins relative paths against workspaceRoot (or current working directory if empty).
// 3. Normalizes directory traversal (e.g., /app/subdir/../.env -> /app/.env).
// 4. Follows all filesystem symlinks (EvalSymlinks). If target does not yet exist,
//    resolves symlinks on the nearest existing ancestor directory and appends remaining segments.
func ResolveCanonicalPath(targetPath, workspaceRoot string) string {
	if targetPath == "" {
		return ""
	}

	trimmed := strings.Trim(targetPath, "\"'")
	if trimmed == "" {
		return ""
	}

	// 1. Tilde expansion (~/ or ~\ or bare ~)
	if trimmed == "~" || strings.HasPrefix(trimmed, "~/") || strings.HasPrefix(trimmed, "~\\") {
		home, err := os.UserHomeDir()
		if err == nil {
			if trimmed == "~" {
				trimmed = home
			} else {
				trimmed = filepath.Join(home, trimmed[2:])
			}
		}
	}

	// 2. Make absolute based on workspaceRoot or CWD
	var absPath string
	normTrimmed := strings.ReplaceAll(trimmed, "\\", "/")
	if filepath.IsAbs(trimmed) || (len(trimmed) >= 3 && trimmed[1] == ':' && (trimmed[2] == '\\' || trimmed[2] == '/')) {
		absPath = filepath.Clean(trimmed)
	} else if strings.HasPrefix(normTrimmed, "/") {
		base := workspaceRoot
		if base == "" {
			if cwd, err := os.Getwd(); err == nil {
				base = cwd
			} else {
				base = "."
			}
		}
		vol := filepath.VolumeName(base)
		if vol != "" {
			absPath = filepath.Clean(vol + filepath.FromSlash(normTrimmed))
		} else {
			absPath = filepath.Clean(normTrimmed)
		}
	} else {
		base := workspaceRoot
		if base == "" {
			if cwd, err := os.Getwd(); err == nil {
				base = cwd
			} else {
				base = "."
			}
		}
		absPath = filepath.Clean(filepath.Join(base, trimmed))
	}

	// 3. Eval symlinks if path exists
	if realPath, err := filepath.EvalSymlinks(absPath); err == nil {
		return filepath.Clean(realPath)
	}

	// 4. Target does not exist yet (e.g., file creation or virtual target):
	// Walk up to find nearest ancestor directory that exists, resolve symlinks on it,
	// and re-append remainder.
	curr := absPath
	var segments []string
	for {
		parent := filepath.Dir(curr)
		base := filepath.Base(curr)
		segments = append([]string{base}, segments...)

		if parent == curr || parent == "" || parent == "." {
			break
		}

		if info, err := os.Stat(parent); err == nil && info.IsDir() {
			if realParent, err := filepath.EvalSymlinks(parent); err == nil {
				resolved := realParent
				for _, seg := range segments {
					resolved = filepath.Join(resolved, seg)
				}
				return filepath.Clean(resolved)
			}
			break
		}
		curr = parent
	}

	return absPath
}

// IsPathOutsideWorkspaceCanonical checks whether targetPath resolves outside
// canonical workspaceRoot after evaluating both symlinks and directory traversal.
func IsPathOutsideWorkspaceCanonical(workspaceRoot, targetPath string) bool {
	if workspaceRoot == "" || targetPath == "" {
		return false
	}

	// Explicit root reference (e.g. "/" or "/*" or "\*") targets the filesystem or drive root,
	// which is strictly outside any project workspace boundary.
	normTarget := strings.ReplaceAll(targetPath, "\\", "/")
	if normTarget == "/" || normTarget == "/*" || normTarget == "/." {
		return true
	}

	canonicalRoot := ResolveCanonicalPath(workspaceRoot, "")
	canonicalTarget := ResolveCanonicalPath(targetPath, workspaceRoot)

	rel, err := filepath.Rel(canonicalRoot, canonicalTarget)
	if err != nil {
		// On Windows, if drives differ (e.g. C: vs D:), Rel returns error
		return true
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.HasPrefix(rel, "../") {
		return true
	}

	return false
}

// IsForbiddenSecretPath detects whether a canonical file path matches sensitive
// secrets, credentials, or protected system resources.
func IsForbiddenSecretPath(canonicalPath string) (bool, string) {
	if canonicalPath == "" {
		return false, ""
	}

	slashPath := strings.ReplaceAll(canonicalPath, "\\", "/")
	cleaned := path.Clean(slashPath)
	lower := strings.ToLower(cleaned)
	base := strings.ToLower(path.Base(cleaned))

	// 1. .env files
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") || strings.Contains(lower, "/.env") {
		return true, "Access to environment secret file (.env) is blocked by secret disclosure policy"
	}

	// 2. SSH key material and configurations
	if strings.Contains(lower, "/.ssh/") || strings.HasSuffix(lower, "/.ssh") {
		return true, "Access to SSH credential directory or key material is blocked by security policy"
	}
	if base == "id_rsa" || base == "id_ed25519" || base == "id_ecdsa" || base == "id_dsa" ||
		base == "authorized_keys" || base == "known_hosts" {
		return true, "Access to private SSH credentials is blocked by security policy"
	}

	// 3. AWS credentials and configuration
	if strings.Contains(lower, "/.aws/") || strings.HasSuffix(lower, "/.aws") {
		return true, "Access to AWS credential directory (~/.aws) is blocked by security policy"
	}

	// 4. POSIX sensitive credential files
	if lower == "/etc/shadow" || lower == "/etc/master.passwd" || lower == "/etc/sudoers" ||
		strings.HasSuffix(lower, "/etc/shadow") || strings.HasSuffix(lower, "/etc/master.passwd") || strings.HasSuffix(lower, "/etc/sudoers") {
		return true, "Access to privileged system authentication database is blocked by security policy"
	}

	return false, ""
}

