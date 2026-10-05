package state

import (
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	resolvedDir string
	dirOnce     sync.Once
	migrateOnce sync.Once
)

// ResetForTesting resets the cached state directory for unit tests.
func ResetForTesting() {
	resolvedDir = ""
	dirOnce = sync.Once{}
	migrateOnce = sync.Once{}
}

// Dir returns the authoritative .bapstate directory following the discovery order:
// 1. Explicit environment variable: BAP_STATE_DIR
// 2. User home directory: ~/.bapstate (if it exists)
// 3. Current working directory: ./.bapstate (if it exists)
// 4. Default: User home ~/.bapstate (with fallback to ./.bapstate if home is unavailable or unwritable)
func Dir() string {
	dirOnce.Do(func() {
		// 1. Explicit environment variable override
		if envDir := os.Getenv("BAP_STATE_DIR"); envDir != "" {
			resolvedDir = envDir
			_ = os.MkdirAll(resolvedDir, 0700)
			return
		}

		home, err := os.UserHomeDir()
		var homeBapstate string
		if err == nil && home != "" {
			homeBapstate = filepath.Join(home, ".bapstate")
		}

		cwdBapstate := ".bapstate"

		// 2. Check user home directory (~/.bapstate)
		if homeBapstate != "" {
			if fi, err := os.Stat(homeBapstate); err == nil && fi.IsDir() {
				resolvedDir = homeBapstate
				return
			}
		}

		// 3. Check current working directory (./.bapstate)
		if fi, err := os.Stat(cwdBapstate); err == nil && fi.IsDir() {
			absCwd, err := filepath.Abs(cwdBapstate)
			if err == nil {
				resolvedDir = absCwd
			} else {
				resolvedDir = cwdBapstate
			}
			return
		}

		// 4. Default in order: create ~/.bapstate if possible, else fallback to ./.bapstate
		if homeBapstate != "" {
			if err := os.MkdirAll(homeBapstate, 0700); err == nil {
				resolvedDir = homeBapstate
				return
			}
		}

		_ = os.MkdirAll(cwdBapstate, 0700)
		absCwd, err := filepath.Abs(cwdBapstate)
		if err == nil {
			resolvedDir = absCwd
		} else {
			resolvedDir = cwdBapstate
		}
	})

	// Ensure legacy migration happens once state dir is determined
	MigrateLegacy()

	return resolvedDir
}

// AuditLogPath returns the default audit log and spool path.
// Precedence: BAP_AUDIT_LOG -> LTD_AUDIT_LOG -> <StateDir>/audit.jsonl
func AuditLogPath() string {
	if env := os.Getenv("BAP_AUDIT_LOG"); env != "" {
		return env
	}
	if env := os.Getenv("LTD_AUDIT_LOG"); env != "" {
		return env
	}
	d := Dir()
	target := filepath.Join(d, "audit.jsonl")

	// If audit.jsonl doesn't exist yet, but ltd-audit.jsonl does, seamlessly use/migrate it
	if _, err := os.Stat(target); os.IsNotExist(err) {
		for _, legacy := range []string{filepath.Join(d, "ltd-audit.jsonl"), "ltd-audit.jsonl"} {
			if fi, err := os.Stat(legacy); err == nil && fi.Size() > 0 {
				_ = copyFile(legacy, target)
				break
			}
		}
	}

	return target
}

// CredentialsPath returns the path to stored agent enrollment credentials.
// Precedence: BAP_CREDENTIALS -> <StateDir>/credentials.json
func CredentialsPath() string {
	if env := os.Getenv("BAP_CREDENTIALS"); env != "" {
		return env
	}
	target := filepath.Join(Dir(), "credentials.json")
	if _, err := os.Stat(target); os.IsNotExist(err) {
		// Fallback check legacy ~/.ltd/credentials.json
		if home, err := os.UserHomeDir(); err == nil {
			legacy := filepath.Join(home, ".ltd", "credentials.json")
			if _, err := os.Stat(legacy); err == nil {
				_ = copyFile(legacy, target)
			}
		}
	}
	return target
}

// ConfigPath returns the path to the central endpoints config file.
// Precedence: BAP_CONFIG -> <StateDir>/config.json
func ConfigPath() string {
	if env := os.Getenv("BAP_CONFIG"); env != "" {
		return env
	}
	target := filepath.Join(Dir(), "config.json")
	if _, err := os.Stat(target); os.IsNotExist(err) {
		// Fallback check legacy ~/.bap/config.json or ~/.ltd/config.json
		if home, err := os.UserHomeDir(); err == nil {
			for _, legacy := range []string{
				filepath.Join(home, ".bap", "config.json"),
				filepath.Join(home, ".ltd", "config.json"),
			} {
				if _, err := os.Stat(legacy); err == nil {
					_ = copyFile(legacy, target)
					break
				}
			}
		}
	}
	return target
}

// PolicyDir returns the directory containing cached Cedar policies and state.
// Precedence: BAP_POLICY_DIR -> <StateDir>/policy
func PolicyDir() string {
	if env := os.Getenv("BAP_POLICY_DIR"); env != "" {
		return env
	}
	target := filepath.Join(Dir(), "policy")
	if _, err := os.Stat(target); os.IsNotExist(err) {
		_ = os.MkdirAll(target, 0700)
		// Fallback check legacy ~/.ltd/policy
		if home, err := os.UserHomeDir(); err == nil {
			legacy := filepath.Join(home, ".ltd", "policy")
			if fi, err := os.Stat(legacy); err == nil && fi.IsDir() {
				_ = copyDir(legacy, target)
			}
		}
	}
	return target
}

// SessionsDir returns the directory where active session and PID markers are stored.
func SessionsDir() string {
	d := filepath.Join(Dir(), "sessions")
	_ = os.MkdirAll(d, 0700)
	return d
}

// WorkspaceSessionPath returns the primary workspace session fallback file.
func WorkspaceSessionPath() string {
	return filepath.Join(Dir(), "session.json")
}

// PromptsDir returns the directory storing captured prompt caches.
func PromptsDir() string {
	d := filepath.Join(Dir(), "prompts")
	_ = os.MkdirAll(d, 0700)
	return d
}

// RiskStatePath returns the path to the local risk state tracking file.
func RiskStatePath() string {
	return filepath.Join(Dir(), "risk_state.json")
}

// MigrateLegacy migrates historical credentials, policy caches, and logs into .bapstate.
func MigrateLegacy() {
	migrateOnce.Do(func() {
		stateDir := resolvedDir
		if stateDir == "" {
			return
		}

		home, _ := os.UserHomeDir()

		// 1. Migrate credentials: ~/.ltd/credentials.json -> <StateDir>/credentials.json
		targetCreds := filepath.Join(stateDir, "credentials.json")
		if _, err := os.Stat(targetCreds); os.IsNotExist(err) && home != "" {
			legacyCreds := filepath.Join(home, ".ltd", "credentials.json")
			if _, err := os.Stat(legacyCreds); err == nil {
				_ = copyFile(legacyCreds, targetCreds)
			}
		}

		// 2. Migrate policy cache: ~/.ltd/policy -> <StateDir>/policy
		targetPolicy := filepath.Join(stateDir, "policy")
		if _, err := os.Stat(targetPolicy); os.IsNotExist(err) || (err == nil && isEmptyDir(targetPolicy)) {
			_ = os.MkdirAll(targetPolicy, 0700)
			if home != "" {
				legacyPolicy := filepath.Join(home, ".ltd", "policy")
				if lFi, err := os.Stat(legacyPolicy); err == nil && lFi.IsDir() {
					_ = copyDir(legacyPolicy, targetPolicy)
				}
			}
		}

		// 3. Migrate sessions: .bap/sessions -> <StateDir>/sessions
		legacySessions := filepath.Join(".bap", "sessions")
		targetSessions := filepath.Join(stateDir, "sessions")
		if lFi, err := os.Stat(legacySessions); err == nil && lFi.IsDir() {
			_ = os.MkdirAll(targetSessions, 0700)
			_ = copyDir(legacySessions, targetSessions)
		}

		// 4. Migrate prompts: .bap/prompts -> <StateDir>/prompts
		legacyPrompts := filepath.Join(".bap", "prompts")
		targetPrompts := filepath.Join(stateDir, "prompts")
		if lFi, err := os.Stat(legacyPrompts); err == nil && lFi.IsDir() {
			_ = os.MkdirAll(targetPrompts, 0700)
			_ = copyDir(legacyPrompts, targetPrompts)
		}

		// 5. Migrate risk state: .bap/risk_state.json -> <StateDir>/risk_state.json
		legacyRisk := filepath.Join(".bap", "risk_state.json")
		targetRisk := filepath.Join(stateDir, "risk_state.json")
		if _, err := os.Stat(targetRisk); os.IsNotExist(err) {
			if _, err := os.Stat(legacyRisk); err == nil {
				_ = copyFile(legacyRisk, targetRisk)
			}
		}
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	_ = os.MkdirAll(filepath.Dir(dst), 0700)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(dst, 0700)
	for _, entry := range entries {
		s := filepath.Join(src, entry.Name())
		d := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			_ = copyDir(s, d)
		} else {
			_ = copyFile(s, d)
		}
	}
	return nil
}

func isEmptyDir(name string) bool {
	f, err := os.Open(name)
	if err != nil {
		return true
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	return err == io.EOF
}
