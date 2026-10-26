package cmd

import "testing"

func clearDevEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"BAP_DEV_OVERRIDE", "BAP_DEV_MODE", "BAP_CISO_TOKEN", "BAP_ADMIN_TOKEN"} {
		t.Setenv(k, "")
	}
}

func TestMCPDevOverrideActive(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{{"", false}, {"maybe", false}, {"1", true}, {"30m", true}, {"48h", false}}
	for _, tc := range cases {
		clearDevEnv(t)
		t.Setenv("BAP_DEV_OVERRIDE", tc.value)
		if got := mcpDevOverrideActive(); got != tc.want {
			t.Errorf("value %q: got %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestMCPDevOverrideNeedsMatchingAdminToken(t *testing.T) {
	clearDevEnv(t)
	t.Setenv("BAP_CISO_TOKEN", "s3cret")
	t.Setenv("BAP_DEV_OVERRIDE", "30m")
	if mcpDevOverrideActive() {
		t.Fatal("override must not activate without the admin token")
	}
	t.Setenv("BAP_ADMIN_TOKEN", "s3cret")
	if !mcpDevOverrideActive() {
		t.Fatal("override should activate with the matching admin token")
	}
}

func TestEnsureMCPSessionLeavesOtherAgentsAlone(t *testing.T) {
	clearDevEnv(t)
	t.Setenv("LTD_SOURCE", "claude-code")
	if got := ensureMCPSession("keep-me", "http://127.0.0.1:1"); got != "keep-me" {
		t.Fatalf("got %q", got)
	}
}

func TestEnsureMCPSessionSkippedUnderDevOverride(t *testing.T) {
	clearDevEnv(t)
	t.Setenv("LTD_SOURCE", "antigravity")
	t.Setenv("BAP_DEV_OVERRIDE", "30m")
	if got := ensureMCPSession("stale-id", "http://127.0.0.1:1"); got != "stale-id" {
		t.Fatalf("enrollment must be skipped under dev override, got %q", got)
	}
}
