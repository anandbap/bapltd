package cmd

import (
	"strings"
	"testing"

	"bap-edge/pkg/version"
)

func TestParseLauncherArgs_StripsBAPFlags(t *testing.T) {
	requireDevOverrideBuild(t) // hook-bypass flags only parse in developer-override builds
	input := []string{"--no-hooks", "-p", "investigate bug", "--verbose"}
	downstream, hooksDisabled, forceFix, _, err := parseLauncherArgs(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hooksDisabled {
		t.Errorf("expected hooksDisabled to be true")
	}
	if forceFix {
		t.Errorf("expected forceFix to be false")
	}
	// Verify --no-hooks is stripped and not sent downstream to Claude
	for _, a := range downstream {
		if a == "--no-hooks" {
			t.Fatalf("BUG: --no-hooks was not stripped from downstream args: %v", downstream)
		}
	}
	if len(downstream) != 3 || downstream[0] != "-p" || downstream[1] != "investigate bug" || downstream[2] != "--verbose" {
		t.Errorf("expected downstream args to preserve claude flags, got: %v", downstream)
	}
}

func TestParseLauncherArgs_VariousHookFlags(t *testing.T) {
	requireDevOverrideBuild(t)
	variants := []string{"--no-hooks", "--disable-hooks", "--hooks-disabled", "--unmonitored", "--bap-hooks=false", "--prompt-only"}
	for _, v := range variants {
		t.Run(v, func(t *testing.T) {
			downstream, hooksDisabled, _, _, err := parseLauncherArgs([]string{v, "test"})
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", v, err)
			}
			if !hooksDisabled {
				t.Errorf("expected hooksDisabled=true for %s", v)
			}
			if len(downstream) != 1 || downstream[0] != "test" {
				t.Errorf("expected downstream=['test'], got %v", downstream)
			}
		})
	}
}

func TestParseLauncherArgs_FixFlag(t *testing.T) {
	downstream, hooksDisabled, forceFix, _, err := parseLauncherArgs([]string{"--fix", "-p", "task"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !forceFix {
		t.Errorf("expected forceFix to be true")
	}
	if hooksDisabled {
		t.Errorf("expected hooksDisabled to be false")
	}
	if len(downstream) != 2 || downstream[0] != "-p" || downstream[1] != "task" {
		t.Errorf("expected downstream args to preserve ['-p', 'task'], got %v", downstream)
	}
}

func TestParseLauncherArgs_ProductionModeRejection(t *testing.T) {
	orig := version.AllowDevOverrides
	version.AllowDevOverrides = "false"
	defer func() { version.AllowDevOverrides = orig }()

	_, _, _, _, err := parseLauncherArgs([]string{"--no-hooks"})
	if err == nil {
		t.Fatalf("expected error in production mode for --no-hooks, got nil")
	}
	if !strings.Contains(err.Error(), "BAP ZERO-TRUST SECURITY VIOLATION") {
		t.Errorf("expected security violation error message, got: %v", err)
	}
}

func TestParseLauncherArgs_ServerURL(t *testing.T) {
	downstream, _, _, srv, err := parseLauncherArgs([]string{"--server=https://bap-controlplane.onrender.com", "-p", "task"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if srv != "https://bap-controlplane.onrender.com" {
		t.Errorf("expected server URL to be parsed, got: %s", srv)
	}
	if len(downstream) != 2 || downstream[0] != "-p" || downstream[1] != "task" {
		t.Errorf("expected downstream args to preserve ['-p', 'task'], got %v", downstream)
	}
}

func TestParseLauncherArgsSeparateServerValue(t *testing.T) {
	args, _, _, server, err := parseLauncherArgs([]string{"--server", "https://bap.example.test", "-p", "task"})
	if err != nil || server != "https://bap.example.test" || len(args) != 2 || args[0] != "-p" {
		t.Fatal(args, server, err)
	}
	if _, _, _, _, err := parseLauncherArgs([]string{"--server"}); err == nil {
		t.Fatal("missing server accepted")
	}
}
