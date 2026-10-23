package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func useManagedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	managedDirFn = func() string { return dir }
	t.Cleanup(func() { managedDirFn = defaultManagedDir; nowFn = time.Now })
	return dir
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, _ := json.Marshal(v)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestManagedLockBeatsEnvAndProjectFiles(t *testing.T) {
	dir := useManagedDir(t)
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"controlplane_url": "https://bap.corp.example:8443/",
		"lock_endpoints":   true,
		"enforcement_mode": "enforce",
	})
	t.Setenv("BAP_SERVER_URL", "http://localhost:8080")
	t.Setenv("BAP_ENFORCEMENT_MODE", "audit")
	t.Setenv("BAP_ENV", "development")

	cfg := ResolveEndpoints()
	if !cfg.Locked {
		t.Fatal("expected locked config")
	}
	if cfg.ControlPlaneURL != "https://bap.corp.example:8443" {
		t.Fatalf("env var overrode managed URL: %q", cfg.ControlPlaneURL)
	}
	if cfg.EnforcementMode != "enforce" {
		t.Fatalf("env var weakened enforcement: %q", cfg.EnforcementMode)
	}
}

func TestProductionEnvironmentImpliesLock(t *testing.T) {
	dir := useManagedDir(t)
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"controlplane_url": "https://bap.corp.example", "environment": "production",
	})
	if cfg := ResolveEndpoints(); !cfg.Locked || cfg.EnforcementMode != "enforce" {
		t.Fatalf("production should lock and default to enforce: %+v", cfg)
	}
}

func TestLockedHasNoLocalhostFallback(t *testing.T) {
	dir := useManagedDir(t)
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{"lock_endpoints": true})
	if got := FallbackControlPlaneURL(); got != "" {
		t.Fatalf("locked config must not offer a localhost fallback, got %q", got)
	}
	if LocalFallbackAllowed() {
		t.Fatal("local fallback must be disallowed when locked")
	}
}

func TestUnlockedKeepsDevelopmentBehaviour(t *testing.T) {
	dir := useManagedDir(t)
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"controlplane_url": "https://dev.example", "environment": "development",
	})
	t.Setenv("BAP_SERVER_URL", "http://localhost:9999")
	cfg := ResolveEndpoints()
	if cfg.Locked || cfg.ControlPlaneURL != "http://localhost:9999" {
		t.Fatalf("unlocked config should still honour env override: %+v", cfg)
	}
}

func lockedWithBreakGlass(t *testing.T, bg map[string]any) EndpointsConfig {
	dir := useManagedDir(t)
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"controlplane_url": "https://bap.corp.example", "lock_endpoints": true,
	})
	writeJSON(t, filepath.Join(dir, "breakglass.json"), bg)
	return ResolveEndpoints()
}

func TestBreakGlassOverridesWhenValid(t *testing.T) {
	cfg := lockedWithBreakGlass(t, map[string]any{
		"controlplane_url": "http://localhost:8080", "operator": "alice", "reason": "central outage INC-1",
		"expires_at": time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
	})
	if cfg.ControlPlaneURL != "http://localhost:8080" || cfg.Override == "" || cfg.ConfigSource != "break_glass" {
		t.Fatalf("valid break-glass not applied: %+v", cfg)
	}
}

func TestBreakGlassRejectedWhenUnsafe(t *testing.T) {
	soon := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	cases := map[string]map[string]any{
		"expired":        {"controlplane_url": "http://localhost:8080", "operator": "a", "reason": "r", "expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)},
		"too long":       {"controlplane_url": "http://localhost:8080", "operator": "a", "reason": "r", "expires_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)},
		"no operator":    {"controlplane_url": "http://localhost:8080", "reason": "r", "expires_at": soon},
		"no reason":      {"controlplane_url": "http://localhost:8080", "operator": "a", "expires_at": soon},
		"bad expiry":     {"controlplane_url": "http://localhost:8080", "operator": "a", "reason": "r", "expires_at": "tomorrow"},
		"missing target": {"operator": "a", "reason": "r", "expires_at": soon},
	}
	for name, bg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := lockedWithBreakGlass(t, bg)
			if cfg.Override != "" || cfg.ControlPlaneURL != "https://bap.corp.example" {
				t.Fatalf("unsafe break-glass accepted: %+v", cfg)
			}
		})
	}
}

func TestBreakGlassIgnoredOutsideManagedDir(t *testing.T) {
	useManagedDir(t) // managed dir stays empty: nothing locked
	project := t.TempDir()
	t.Chdir(project)
	writeJSON(t, filepath.Join(project, "breakglass.json"), map[string]any{
		"controlplane_url": "http://localhost:8080", "operator": "a", "reason": "r",
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if cfg := ResolveEndpoints(); cfg.Override != "" {
		t.Fatalf("a project-level breakglass file must never be honoured: %+v", cfg)
	}
}
