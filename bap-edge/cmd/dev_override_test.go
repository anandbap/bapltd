package cmd

import (
	"os"
	"testing"

	"bap-edge/pkg/version"
)

func TestDevOverride_AgentInvocationBlocked(t *testing.T) {
	t.Setenv("BAP_ENVIRONMENT", "development")
	t.Setenv("LTD_SOURCE", "claude-code")
	err := RunDevOverride([]string{"on"})
	if err == nil {
		t.Fatal("expected AI agent invocation of dev-override to be blocked, but succeeded")
	}
}

func TestDevOverride_ProductionStrictlyBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origWd) }()

	// Even if someone tries to enable dev override in production:
	t.Setenv("BAP_ENVIRONMENT", "production")
	t.Setenv("BAP_DEV_OVERRIDE", "1")
	t.Setenv("LTD_SOURCE", "human")

	// 1. devOverrideActive MUST return false in production
	active, banner := devOverrideActive()
	if active {
		t.Fatalf("SECURITY VIOLATION: devOverrideActive must be false in production, got active=true (banner=%q)", banner)
	}

	// 2. bapedge dev-override on MUST fail in production
	err := RunDevOverride([]string{"on"})
	if err == nil {
		t.Fatal("expected RunDevOverride on to be blocked in production, but succeeded")
	}
}

func TestDevOverride_DevelopmentModeAllowedWithoutAdminToken(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origWd) }()

	t.Setenv("BAP_ENVIRONMENT", "development")
	t.Setenv("BAP_DEV_OVERRIDE", "")
	t.Setenv("BAP_DEV_MODE", "")
	t.Setenv("LTD_SOURCE", "human")

	// 1. Initially inactive
	active, _ := devOverrideActive()
	if active {
		t.Fatal("expected initially inactive")
	}

	// 2. Enable without admin token in dev environment
	err := RunDevOverride([]string{"on", "--duration", "2h"})
	if err != nil {
		t.Fatalf("expected success in development environment without token, got: %v", err)
	}

	// 3. Verify active
	active, banner := devOverrideActive()
	if !active {
		t.Fatal("expected devOverrideActive to be true")
	}
	if banner == "" {
		t.Fatal("expected banner to be non-empty")
	}

	// 4. Disable
	err = RunDevOverride([]string{"off"})
	if err != nil {
		t.Fatalf("failed to turn off dev-override: %v", err)
	}
	active, _ = devOverrideActive()
	if active {
		t.Fatal("expected devOverrideActive to be false after off")
	}
}

func TestDevOverride_CompiledOutWhenAllowDevOverridesFalse(t *testing.T) {
	orig := version.AllowDevOverrides
	version.AllowDevOverrides = "false"
	defer func() { version.AllowDevOverrides = orig }()

	t.Setenv("BAP_ENVIRONMENT", "development")
	t.Setenv("BAP_DEV_OVERRIDE", "1")
	t.Setenv("LTD_SOURCE", "human")

	active, _ := devOverrideActive()
	if active {
		t.Fatal("expected devOverrideActive to be false when AllowDevOverrides is false")
	}

	err := RunDevOverride([]string{"on"})
	if err == nil {
		t.Fatal("expected RunDevOverride on to fail when AllowDevOverrides is false")
	}

	err = RunDevOverride([]string{"status"})
	if err == nil {
		t.Fatal("expected RunDevOverride status to fail when AllowDevOverrides is false")
	}
}
