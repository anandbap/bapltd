package config

import (
	"path/filepath"
	"testing"
)

func TestEnrollmentIsMasterReportingDestination(t *testing.T) {
	managed := useManagedDir(t)
	path := filepath.Join(t.TempDir(), "synthetic-enrollment.json")
	t.Setenv("BAP_CREDENTIALS", path)
	t.Setenv("BAP_SERVER_URL", "https://stale-project.example")
	writeJSON(t, path, map[string]any{"server_url": "https://enrolled.example/", "session_token": "synthetic-proof", "instance_id": "machine"})
	if cfg := ResolveEndpoints(); cfg.ControlPlaneURL != "https://enrolled.example" || cfg.ConfigSource != "workstation_enrollment" {
		t.Fatalf("enrollment overridden: %+v", cfg)
	}
	for _, requested := range []string{"", "off", "https://other.example"} {
		if got := ReportingEndpoint(requested); got != "https://enrolled.example" {
			t.Fatalf("reporting redirected: %q", got)
		}
	}
	writeJSON(t, filepath.Join(managed, "config.json"), map[string]any{"controlplane_url": "https://managed.example", "lock_endpoints": true})
	if got := ReportingEndpoint("https://other.example"); got != "https://managed.example" {
		t.Fatalf("managed lock weakened: %q", got)
	}
	if CheckReportingEnrollment("https://managed.example") == nil {
		t.Fatal("conflicting enrollment must queue evidence, not send it elsewhere")
	}
}
