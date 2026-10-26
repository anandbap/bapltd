package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

const maxDevOverrideWindow = 12 * time.Hour
const defaultDevOverrideWindow = 4 * time.Hour

type devOverrideFile struct {
	Active       bool      `json:"active"`
	ActivatedAt  time.Time `json:"activated_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	AuthorizedBy string    `json:"authorized_by"`
	Reason       string    `json:"reason,omitempty"`
}

// resolveEnvironment returns the deployment environment from BAP_ENVIRONMENT or config.
// Unset or unknown environments default strictly to "production" (fail-closed).
func resolveEnvironment() string {
	if e := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_ENVIRONMENT"))); e != "" {
		return e
	}
	cfgCandidates := []string{
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
		"../bap-config.json",
	}
	if home, _ := os.UserHomeDir(); home != "" {
		cfgCandidates = append(cfgCandidates,
			filepath.Join(home, ".bapstate", "config.json"),
			filepath.Join(home, ".bap", "config.json"),
			filepath.Join(home, ".bap", "bap-config.json"),
		)
	}
	for _, p := range cfgCandidates {
		if data, err := os.ReadFile(p); err == nil {
			var cfg struct {
				Environment string `json:"environment"`
			}
			if json.Unmarshal(data, &cfg) == nil && cfg.Environment != "" {
				return strings.ToLower(strings.TrimSpace(cfg.Environment))
			}
		}
	}
	return "production"
}

// isDeveloperModeAllowed returns true ONLY when:
// 1. The environment is explicitly "development", "dev", or "local".
// 2. Developer feature flag is enabled ("developer_features": true, "developer_mode": true, or BAP_DEVELOPER_FEATURES=1).
// In "production", "staging", or unconfigured environments, it ALWAYS returns false (fail-closed).
func isDeveloperModeAllowed() (bool, string) {
	env := resolveEnvironment()
	switch env {
	case "development", "dev", "local":
		// valid dev environment
	default:
		return false, fmt.Sprintf("environment is %q (developer override is strictly prohibited in production)", env)
	}

	// Check feature flag
	if e := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_DEVELOPER_FEATURES"))); e == "true" || e == "1" || e == "on" {
		return true, ""
	}
	if e := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_DEVELOPER_MODE"))); e == "true" || e == "1" || e == "on" {
		return true, ""
	}

	cfgCandidates := []string{
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
	}
	for _, p := range cfgCandidates {
		if data, err := os.ReadFile(p); err == nil {
			var cfg struct {
				DeveloperFeatures bool `json:"developer_features"`
				DeveloperMode     bool `json:"developer_mode"`
			}
			if json.Unmarshal(data, &cfg) == nil {
				if cfg.DeveloperFeatures || cfg.DeveloperMode {
					return true, ""
				}
			}
		}
	}

	// If environment was explicitly configured as development/local, permit dev features by default in dev
	if env == "development" || env == "dev" || env == "local" {
		return true, ""
	}

	return false, "developer_features flag is not enabled"
}

func parseDevOverrideExpiry(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	lower := strings.ToLower(raw)
	if lower == "1" || lower == "true" || lower == "on" || lower == "yes" || lower == "active" {
		return time.Now().Add(defaultDevOverrideWindow), true
	}
	if dur, err := time.ParseDuration(raw); err == nil && dur > 0 {
		if dur > maxDevOverrideWindow {
			dur = maxDevOverrideWindow
		}
		return time.Now().Add(dur), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func devOverrideActive() (bool, string) {
	// GATING INVARIANT: Developer features must be allowed (strictly prohibited in production)
	if allowed, _ := isDeveloperModeAllowed(); !allowed {
		return false, ""
	}

	// 1. Check environment variable BAP_DEV_OVERRIDE or BAP_DEV_MODE
	raw := strings.TrimSpace(os.Getenv("BAP_DEV_OVERRIDE"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("BAP_DEV_MODE"))
	}
	if raw != "" {
		if until, ok := parseDevOverrideExpiry(raw); ok {
			now := time.Now()
			if until.After(now) {
				return true, fmt.Sprintf("[BAP DEV OVERRIDE ACTIVE until %s] Anti-tampering checks on BAP files are suspended; credentials, revocation and policy still apply.", until.Format(time.RFC3339))
			}
		}
	}

	// 2. Check marker file: .bap/dev-override.json or ~/.bapstate/dev-override.json
	markerCandidates := []string{
		filepath.Join(".bap", "dev-override.json"),
		"dev-override.json",
	}
	if home, _ := os.UserHomeDir(); home != "" {
		markerCandidates = append(markerCandidates, filepath.Join(home, ".bapstate", "dev-override.json"))
	}
	for _, m := range markerCandidates {
		if data, err := os.ReadFile(m); err == nil {
			var d devOverrideFile
			if json.Unmarshal(data, &d) == nil && d.Active {
				if d.ExpiresAt.After(time.Now()) {
					return true, fmt.Sprintf("[BAP DEV OVERRIDE ACTIVE until %s] Anti-tampering checks on BAP files are suspended; credentials, revocation and policy still apply.", d.ExpiresAt.Format(time.RFC3339))
				}
			}
		}
	}

	// 3. Check bap-config.json
	cfgCandidates := []string{
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
	}
	for _, p := range cfgCandidates {
		if data, err := os.ReadFile(p); err == nil {
			var cfg struct {
				DevOverride bool `json:"dev_override"`
			}
			if json.Unmarshal(data, &cfg) == nil && cfg.DevOverride {
				return true, "[BAP DEV OVERRIDE ACTIVE via config] Anti-tampering checks on BAP files are suspended; credentials, revocation and policy still apply."
			}
		}
	}

	return false, ""
}

// RunDevOverride manages the developer override window for BAP self-development.
func RunDevOverride(args []string) error {
	fs := flag.NewFlagSet("dev-override", flag.ContinueOnError)
	durFlag := fs.Duration("duration", defaultDevOverrideWindow, "Duration of the dev override window (default 4h, max 12h)")
	reasonFlag := fs.String("reason", "BAP local development override", "Reason for developer override")

	if len(args) == 0 {
		return showDevOverrideStatus()
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "status":
		return showDevOverrideStatus()

	case "on", "enable":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		// Security Invariant 1: Production Lockdown (Fail-Closed)
		if allowed, reason := isDeveloperModeAllowed(); !allowed {
			return fmt.Errorf("⛔ Feature Locked: Developer Override is a developers-only feature. It is completely blocked in production (%s).\n   Developer features require 'environment': 'development' in bap-config.json or BAP_ENVIRONMENT=development", reason)
		}

		// Security Invariant 2: Prevent AI agents from enabling dev-override autonomously
		if source := os.Getenv("LTD_SOURCE"); source != "" && source != "human" && source != "terminal" {
			return fmt.Errorf("⛔ Security Invariant Violation: AI agent %q cannot activate developer override. This command requires interactive human administrator authorization", source)
		}
		if sessionID := os.Getenv("BAP_SESSION_ID"); sessionID != "" && strings.Contains(sessionID, "agent") {
			return fmt.Errorf("⛔ Security Invariant Violation: Autonomous agent session cannot activate developer override")
		}

		dur := *durFlag
		if dur > maxDevOverrideWindow {
			fmt.Printf("⚠️  Requested duration %s exceeds maximum window (%s). Capping at %s.\n", dur, maxDevOverrideWindow, maxDevOverrideWindow)
			dur = maxDevOverrideWindow
		}

		userName := "developer"
		if u, err := user.Current(); err == nil && u.Username != "" {
			userName = u.Username
		}

		activatedAt := time.Now()
		expiresAt := activatedAt.Add(dur)

		d := devOverrideFile{
			Active:       true,
			ActivatedAt:  activatedAt,
			ExpiresAt:    expiresAt,
			AuthorizedBy: userName,
			Reason:       *reasonFlag,
		}

		data, _ := json.MarshalIndent(d, "", "  ")
		_ = os.MkdirAll(".bap", 0755)
		if err := os.WriteFile(filepath.Join(".bap", "dev-override.json"), data, 0644); err != nil {
			return fmt.Errorf("failed to write dev-override file: %w", err)
		}

		fmt.Printf("✅ BAP Developer Override enabled until %s (%s window)\n", expiresAt.Format(time.RFC3339), dur)
		fmt.Printf("   Environment:   %s [DEVELOPER MODE]\n", resolveEnvironment())
		fmt.Printf("   Authorized by: %s\n", userName)
		fmt.Println("   Anti-tampering checks on BAP protected files/binaries are suspended.")
		fmt.Println("   Credential files (.env, AWS, SSH keys) and revocations remain 100% enforced.")
		fmt.Println("   To disable at any time, run: bapedge dev-override off")
		return nil

	case "off", "disable":
		p := filepath.Join(".bap", "dev-override.json")
		_ = os.Remove(p)
		if home, _ := os.UserHomeDir(); home != "" {
			_ = os.Remove(filepath.Join(home, ".bapstate", "dev-override.json"))
		}
		fmt.Println("🔒 BAP Developer Override disabled. Full anti-tampering enforcement restored.")
		return nil

	default:
		return fmt.Errorf("unknown dev-override action %q. Use 'on', 'off', or 'status'", sub)
	}
}

func showDevOverrideStatus() error {
	allowed, reason := isDeveloperModeAllowed()
	if !allowed {
		fmt.Printf("🔒 BAP Developer Override is PERMANENTLY DISABLED (%s).\n", reason)
		fmt.Println("   This feature is locked out of production environments by security policy.")
		return nil
	}

	active, banner := devOverrideActive()
	if active {
		fmt.Println(banner)
	} else {
		fmt.Println("🔒 BAP Developer Override is INACTIVE. Full anti-tampering enforcement is active.")
		fmt.Printf("   Environment: %s [DEVELOPER MODE]\n", resolveEnvironment())
		fmt.Println("   To enable for BAP development: bapedge dev-override on [--duration 4h]")
		fmt.Println("   Or set environment variable:  $env:BAP_DEV_OVERRIDE=\"1\"")
	}
	return nil
}
