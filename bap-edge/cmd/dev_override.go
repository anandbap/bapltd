package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxDevOverrideWindow = 12 * time.Hour

type devOverrideFile struct {
	Active    bool      `json:"active"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
}

func parseDevOverrideExpiry(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	lower := strings.ToLower(raw)
	if lower == "1" || lower == "true" || lower == "on" || lower == "yes" || lower == "active" {
		return time.Now().Add(maxDevOverrideWindow), true
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

// RunDevOverride manages the developer override window for BAP development.
func RunDevOverride(args []string) error {
	fs := flag.NewFlagSet("dev-override", flag.ContinueOnError)
	durFlag := fs.Duration("duration", 12*time.Hour, "Duration of the dev override window (max 12h)")

	if len(args) == 0 {
		return showDevOverrideStatus()
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "status":
		return showDevOverrideStatus()
	case "on", "enable":
		_ = fs.Parse(args[1:])
		dur := *durFlag
		if dur > maxDevOverrideWindow {
			dur = maxDevOverrideWindow
		}
		expiresAt := time.Now().Add(dur)
		d := devOverrideFile{
			Active:    true,
			ExpiresAt: expiresAt,
			Reason:    "BAP local development override",
		}
		data, _ := json.MarshalIndent(d, "", "  ")
		_ = os.MkdirAll(".bap", 0755)
		if err := os.WriteFile(filepath.Join(".bap", "dev-override.json"), data, 0644); err != nil {
			return fmt.Errorf("failed to write dev-override file: %w", err)
		}
		fmt.Printf("✅ BAP Developer Override enabled until %s (%s window)\n", expiresAt.Format(time.RFC3339), dur)
		fmt.Println("   Anti-tampering checks on BAP protected files/binaries are suspended.")
		fmt.Println("   To disable, run: bapedge dev-override off")
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
		fmt.Println("🔒 BAP Developer Override is INACTIVE. Full anti-tampering enforcement is active.")
		fmt.Println("   To enable for BAP development: bapedge dev-override on [--duration 8h]")
		fmt.Println("   Or set environment variable:  $env:BAP_DEV_OVERRIDE=\"1\"")
	}
	return nil
}
