package cmd

import (
	"os"
	"testing"

	"bap-edge/internal/config"
)

func TestStepUp_ServerURLResolution(t *testing.T) {
	// 1. Env override BAP_SERVER_URL
	t.Setenv("BAP_SERVER_URL", "https://custom-cp.corp.internal")
	t.Setenv("BAP_CONTROL_PLANE_URL", "")
	if got := resolveStepUpServerURL(); got != "https://custom-cp.corp.internal" {
		t.Fatalf("expected https://custom-cp.corp.internal, got: %s", got)
	}

	// 2. Env override BAP_CONTROL_PLANE_URL
	t.Setenv("BAP_SERVER_URL", "")
	t.Setenv("BAP_CONTROL_PLANE_URL", "https://render-cp.example.com")
	if got := resolveStepUpServerURL(); got != "https://render-cp.example.com" {
		t.Fatalf("expected https://render-cp.example.com, got: %s", got)
	}

	// 3. Fallback to config.ResolveEndpoints()
	t.Setenv("BAP_SERVER_URL", "")
	t.Setenv("BAP_CONTROL_PLANE_URL", "")
	got := resolveStepUpServerURL()
	if got == "" || got == "http://localhost:8443" && config.DefaultControlPlaneURL != "http://localhost:8443" {
		t.Fatalf("stepup should never default to localhost:8443 when central CP is configured, got: %s", got)
	}
	_ = os.DevNull
}
