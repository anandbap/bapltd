package cmd

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	Active      bool      `json:"active"`
	ActivatedAt time.Time `json:"activated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	AuthorizedBy string   `json:"authorized_by"`
	AuthMethod  string    `json:"auth_method"`
	Reason      string    `json:"reason,omitempty"`
	Signature   string    `json:"signature,omitempty"`
}

func computeOverrideSignature(d devOverrideFile, secret string) string {
	payload := fmt.Sprintf("%v|%d|%d|%s|%s", d.Active, d.ActivatedAt.Unix(), d.ExpiresAt.Unix(), d.AuthorizedBy, d.AuthMethod)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func resolveConfiguredAdminToken() string {
	if t := strings.TrimSpace(os.Getenv("BAP_CISO_TOKEN")); t != "" {
		return t
	}
	cfgCandidates := []string{
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
	}
	if home, _ := os.UserHomeDir(); home != "" {
		cfgCandidates = append(cfgCandidates,
			filepath.Join(home, ".bapstate", "config.json"),
			filepath.Join(home, ".bap", "config.json"),
		)
	}
	for _, p := range cfgCandidates {
		if data, err := os.ReadFile(p); err == nil {
			var cfg struct {
				AdminToken       string `json:"admin_token"`
				CISOToken        string `json:"ciso_token"`
				DevOverrideToken string `json:"dev_override_token"`
			}
			if json.Unmarshal(data, &cfg) == nil {
				if cfg.AdminToken != "" {
					return cfg.AdminToken
				}
				if cfg.CISOToken != "" {
					return cfg.CISOToken
				}
				if cfg.DevOverrideToken != "" {
					return cfg.DevOverrideToken
				}
			}
		}
	}
	return ""
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
	// 1. Check environment variable BAP_DEV_OVERRIDE or BAP_DEV_MODE
	raw := strings.TrimSpace(os.Getenv("BAP_DEV_OVERRIDE"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("BAP_DEV_MODE"))
	}
	if raw != "" {
		// If an admin token is configured, BAP_DEV_OVERRIDE via env must match token or valid expiry
		configuredAdmin := resolveConfiguredAdminToken()
		if configuredAdmin != "" {
			providedToken := strings.TrimSpace(os.Getenv("BAP_ADMIN_TOKEN"))
			if providedToken == "" {
				providedToken = raw
			}
			if subtle.ConstantTimeCompare([]byte(providedToken), []byte(configuredAdmin)) != 1 {
				// Mismatch with admin token: cannot activate via env
				return false, ""
			}
		}
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
	configuredAdmin := resolveConfiguredAdminToken()
	for _, m := range markerCandidates {
		if data, err := os.ReadFile(m); err == nil {
			var d devOverrideFile
			if json.Unmarshal(data, &d) == nil && d.Active {
				// Verify cryptographic signature if admin token is configured
				if configuredAdmin != "" && d.Signature != "" {
					expectedSig := computeOverrideSignature(d, configuredAdmin)
					if subtle.ConstantTimeCompare([]byte(d.Signature), []byte(expectedSig)) != 1 {
						continue // signature mismatch / tampered override file
					}
				}
				if d.ExpiresAt.After(time.Now()) {
					return true, fmt.Sprintf("[BAP DEV OVERRIDE ACTIVE until %s (Auth: %s)] Anti-tampering checks on BAP files are suspended; credentials, revocation and policy still apply.", d.ExpiresAt.Format(time.RFC3339), d.AuthMethod)
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
				// If admin token is configured, config file override alone is not permitted without token
				if configuredAdmin == "" {
					return true, "[BAP DEV OVERRIDE ACTIVE via config] Anti-tampering checks on BAP files are suspended; credentials, revocation and policy still apply."
				}
			}
		}
	}

	return false, ""
}

// RunDevOverride manages the developer override window for BAP development.
func RunDevOverride(args []string) error {
	fs := flag.NewFlagSet("dev-override", flag.ContinueOnError)
	durFlag := fs.Duration("duration", defaultDevOverrideWindow, "Duration of the dev override window (default 4h, max 12h)")
	tokenFlag := fs.String("token", "", "Admin / CISO token required to authorize dev-override")
	reasonFlag := fs.String("reason", "BAP local development override", "Reason or ticket for developer override")

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

		// Security Invariant 1: Prevent AI agents from enabling dev-override autonomously
		if source := os.Getenv("LTD_SOURCE"); source != "" && source != "human" && source != "terminal" {
			return fmt.Errorf("⛔ Security Invariant Violation: AI agent %q cannot activate developer override. This command requires interactive human administrator authorization", source)
		}
		if sessionID := os.Getenv("BAP_SESSION_ID"); sessionID != "" && strings.Contains(sessionID, "agent") {
			return fmt.Errorf("⛔ Security Invariant Violation: Autonomous agent session cannot activate developer override")
		}

		// Security Invariant 2: Admin Token Authorization
		configuredAdmin := resolveConfiguredAdminToken()
		providedToken := strings.TrimSpace(*tokenFlag)
		if providedToken == "" {
			providedToken = strings.TrimSpace(os.Getenv("BAP_ADMIN_TOKEN"))
		}

		authMethod := "human_terminal"
		if configuredAdmin != "" {
			if providedToken == "" {
				return fmt.Errorf("⛔ Authorization Required: An Admin Token is required to activate dev-override.\n   Usage: bapedge dev-override on --token <ADMIN_TOKEN> [--duration 4h]")
			}
			if subtle.ConstantTimeCompare([]byte(providedToken), []byte(configuredAdmin)) != 1 {
				return fmt.Errorf("⛔ Authorization Failed: Invalid Admin Token. Access denied")
			}
			authMethod = "admin_token"
		} else if providedToken != "" {
			authMethod = "admin_token"
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
			AuthMethod:   authMethod,
			Reason:       *reasonFlag,
		}

		// Sign override file if admin token or secret is available
		secret := configuredAdmin
		if secret == "" {
			secret = providedToken
		}
		if secret != "" {
			d.Signature = computeOverrideSignature(d, secret)
		}

		data, _ := json.MarshalIndent(d, "", "  ")
		_ = os.MkdirAll(".bap", 0755)
		if err := os.WriteFile(filepath.Join(".bap", "dev-override.json"), data, 0644); err != nil {
			return fmt.Errorf("failed to write dev-override file: %w", err)
		}

		fmt.Printf("✅ BAP Developer Override enabled until %s (%s window)\n", expiresAt.Format(time.RFC3339), dur)
		fmt.Printf("   Authorized by: %s (Method: %s)\n", userName, authMethod)
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
	active, banner := devOverrideActive()
	if active {
		fmt.Println(banner)
	} else {
		configuredAdmin := resolveConfiguredAdminToken()
		fmt.Println("🔒 BAP Developer Override is INACTIVE. Full anti-tampering enforcement is active.")
		if configuredAdmin != "" {
			fmt.Println("   Admin Token protection is ENABLED for this environment.")
			fmt.Println("   To enable: bapedge dev-override on --token <ADMIN_TOKEN> [--duration 4h]")
		} else {
			fmt.Println("   To enable for BAP development: bapedge dev-override on [--token <token>] [--duration 4h]")
			fmt.Println("   To protect with an Admin Token: configure 'admin_token' in bap-config.json or set BAP_ADMIN_TOKEN")
		}
	}
	return nil
}
