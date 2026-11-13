package authz

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BAP-933/934: a trust entry opens a folder to the agent (reads, and the listed mutations). It must
// never open filesystem roots, the home directory (or anything above it), operating-system folders,
// or credential stores, no matter who or what asks for it.

var systemTrustPrefixes = []string{
	"c:/windows", "c:/program files", "c:/program files (x86)", "c:/programdata",
	"/etc", "/usr", "/bin", "/sbin", "/sys", "/proc", "/boot", "/dev", "/lib", "/lib64", "/var/lib", "/private/etc", "/private/var/db", "/system", "/library",
}

// ValidateTrustTarget returns an error when path is too broad or too sensitive to ever be trusted.
func ValidateTrustTarget(p string) error {
	clean := filepath.Clean(p)
	// Normalize Windows separators explicitly: filepath.ToSlash is a no-op for backslashes on Linux/macOS,
	// where a Windows-style path (C:\Windows) would otherwise slip past the checks below.
	slash := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(clean), "\\", "/"))

	if IsFilesystemRootTarget(clean) || slash == "/" || (len(slash) == 3 && slash[1] == ':' && slash[2] == '/') || (len(slash) == 2 && slash[1] == ':') {
		return fmt.Errorf("refusing to trust a filesystem or drive root: %s", p)
	}
	if isProtectedCredentialPath(clean) {
		return fmt.Errorf("refusing to trust a credential location: %s", p)
	}
	for _, pre := range systemTrustPrefixes {
		if slash == pre || strings.HasPrefix(slash, pre+"/") {
			return fmt.Errorf("refusing to trust an operating-system folder: %s", p)
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		// Compare against the home directory as written AND as the filesystem resolves it (8.3 short
		// names, symlinks such as /Users -> /private/...): callers pass canonicalised paths.
		homes := []string{filepath.Clean(home)}
		if resolved, rErr := filepath.EvalSymlinks(home); rErr == nil && resolved != "" {
			homes = append(homes, filepath.Clean(resolved))
		}
		cleans := []string{clean}
		if resolved, rErr := filepath.EvalSymlinks(clean); rErr == nil && resolved != "" {
			cleans = append(cleans, filepath.Clean(resolved))
		}
		for _, h := range homes {
			for _, c := range cleans {
				if strings.EqualFold(c, h) {
					return fmt.Errorf("refusing to trust the whole home directory (%s); trust a specific subfolder such as Downloads", p)
				}
				// An ancestor of the home directory (C:\Users, C:\) would expose it.
				if rel, relErr := filepath.Rel(c, h); relErr == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
					return fmt.Errorf("refusing to trust %s: it contains the home directory", p)
				}
			}
		}
	}
	return nil
}
