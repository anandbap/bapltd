package main

import (
	"testing"
)

func TestIsHooksDisabled(t *testing.T) {
	isolate(t)

	cases := []struct {
		name     string
		envKey   string
		envVal   string
		expected bool
	}{
		{"default enabled", "", "", false},
		{"BAP_HOOKS false", "BAP_HOOKS", "false", true},
		{"BAP_HOOKS 0", "BAP_HOOKS", "0", true},
		{"BAP_HOOKS off", "BAP_HOOKS", "off", true},
		{"BAP_DISABLE_HOOKS 1", "BAP_DISABLE_HOOKS", "1", true},
		{"BAP_DISABLE_HOOKS true", "BAP_DISABLE_HOOKS", "true", true},
		{"BAP_MODE disabled", "BAP_MODE", "disabled", true},
		{"BAP_MODE off", "BAP_MODE", "off", true},
		{"BAP_HOOKS true", "BAP_HOOKS", "true", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolate(t)
			t.Setenv("BAP_HOOKS", "")
			t.Setenv("BAP_DISABLE_HOOKS", "")
			t.Setenv("BAP_MODE", "")
			if tc.envKey != "" {
				t.Setenv(tc.envKey, tc.envVal)
			}
			got := isHooksDisabled()
			if got != tc.expected {
				t.Errorf("isHooksDisabled() for %s=%s got %v, want %v", tc.envKey, tc.envVal, got, tc.expected)
			}
		})
	}
}

func TestIsStrictToolEnforcementMandated(t *testing.T) {
	isolate(t)

	// Default: Tier 2 is OFF by default -> Tier 1 Standard
	t.Run("default is Tier 1 Standard", func(t *testing.T) {
		isolate(t)
		t.Setenv("BAP_TIER", "")
		t.Setenv("BAP_STRICT_TOOLS", "")
		t.Setenv("BAP_HOOKS", "")
		if isStrictToolEnforcementMandated() {
			t.Errorf("expected isStrictToolEnforcementMandated to be false by default")
		}
	})

	t.Run("BAP_TIER=2 enables strict enforcement", func(t *testing.T) {
		isolate(t)
		t.Setenv("BAP_TIER", "2")
		if !isStrictToolEnforcementMandated() {
			t.Errorf("expected isStrictToolEnforcementMandated to be true for BAP_TIER=2")
		}
	})

	t.Run("BAP_TIER=1 forces standard mode", func(t *testing.T) {
		isolate(t)
		t.Setenv("BAP_TIER", "1")
		t.Setenv("BAP_STRICT_TOOLS", "true")
		if isStrictToolEnforcementMandated() {
			t.Errorf("expected isStrictToolEnforcementMandated to be false for BAP_TIER=1")
		}
	})

	t.Run("BAP_STRICT_TOOLS=true enables strict enforcement", func(t *testing.T) {
		isolate(t)
		t.Setenv("BAP_TIER", "")
		t.Setenv("BAP_STRICT_TOOLS", "true")
		if !isStrictToolEnforcementMandated() {
			t.Errorf("expected isStrictToolEnforcementMandated to be true for BAP_STRICT_TOOLS=true")
		}
	})
}
