package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// MaxBreakGlassTTL caps how long a break-glass override may stay valid. An
// override that expires further out than this is ignored, so a forgotten
// override cannot become a permanent bypass.
const MaxBreakGlassTTL = 24 * time.Hour

// BreakGlass is an emergency, time-boxed override of the locked control plane
// endpoint. It is read only from the managed directory, which on a correctly
// deployed machine is writable by administrators only. It is deliberately not
// settable through environment variables or project/user files, because an
// agent or a compromised repo could write those.
type BreakGlass struct {
	ControlPlaneURL string `json:"controlplane_url"`
	Operator        string `json:"operator"`
	Reason          string `json:"reason"`
	ExpiresAt       string `json:"expires_at"` // RFC 3339
}

var (
	managedDirFn = defaultManagedDir
	nowFn        = time.Now
)

func defaultManagedDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "BAP")
		}
		return ""
	}
	return "/etc/bap"
}

// loadManaged returns the system-wide managed configuration, if one exists.
func loadManaged() (*EndpointsConfig, string) {
	dir := managedDirFn()
	if dir == "" {
		return nil, ""
	}
	for _, name := range []string{"config.json", "bap-config.json"} {
		p := filepath.Join(dir, name)
		if c, err := loadConfigFile(p); err == nil {
			return c, p
		}
	}
	return nil, ""
}

// isLocked reports whether a managed config demands central control: either it
// sets lock_endpoints, or it declares a production environment.
func isLocked(c *EndpointsConfig) bool {
	return c != nil && (c.LockEndpoints || strings.EqualFold(strings.TrimSpace(c.Environment), "production"))
}

// loadBreakGlass returns a currently valid override from the managed directory.
func loadBreakGlass() *BreakGlass {
	dir := managedDirFn()
	if dir == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, "breakglass.json"))
	if err != nil {
		return nil
	}
	var bg BreakGlass
	if json.Unmarshal(data, &bg) != nil || strings.TrimSpace(bg.ControlPlaneURL) == "" {
		return nil
	}
	if strings.TrimSpace(bg.Operator) == "" || strings.TrimSpace(bg.Reason) == "" {
		return nil // an override must name who did it and why
	}
	exp, err := time.Parse(time.RFC3339, bg.ExpiresAt)
	if err != nil {
		return nil
	}
	now := nowFn()
	if !exp.After(now) || exp.After(now.Add(MaxBreakGlassTTL)) {
		return nil
	}
	return &bg
}

// resolveLocked builds the configuration from the managed file alone. Nothing
// else (environment variables, project files, user files, localhost defaults)
// can change an endpoint or weaken the enforcement mode.
func resolveLocked(m *EndpointsConfig, path string) EndpointsConfig {
	cfg := EndpointsConfig{
		ControlPlaneURL: strings.TrimRight(m.ControlPlaneURL, "/"),
		GatewayURL:      strings.TrimRight(m.GatewayURL, "/"),
		EnvoyURL:        strings.TrimRight(m.EnvoyURL, "/"),
		TrustDomain:     m.TrustDomain,
		Environment:     m.Environment,
		EnforcementMode: strings.ToLower(strings.TrimSpace(m.EnforcementMode)),
		ConfigSource:    path,
		OIDC:            m.OIDC,
		LockEndpoints:   true,
		Locked:          true,
	}
	if cfg.EnforcementMode == "" {
		cfg.EnforcementMode = "enforce"
	}
	if bg := loadBreakGlass(); bg != nil {
		cfg.ControlPlaneURL = strings.TrimRight(bg.ControlPlaneURL, "/")
		cfg.ConfigSource = "break_glass"
		cfg.Override = fmt.Sprintf("BREAK-GLASS ACTIVE until %s by %s: %s", bg.ExpiresAt, bg.Operator, bg.Reason)
	}
	return cfg
}

// FallbackControlPlaneURL returns the local standalone fallback address, or an
// empty string when endpoints are centrally locked. Callers must treat an empty
// result as "no central server reachable": use the cached local policy and queue
// records, but never talk to a local stand-in.
func FallbackControlPlaneURL() string {
	if ResolveEndpoints().Locked {
		return ""
	}
	return DefaultControlPlaneURL
}

// LocalFallbackAllowed reports whether probing localhost when the configured
// server is unreachable is permitted.
func LocalFallbackAllowed() bool {
	return !ResolveEndpoints().Locked
}
