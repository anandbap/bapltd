package main

import (
	"os"
	"testing"
	"time"
)

// isolate runs the test in an empty workspace and home so no real BAP config is picked up.
func isolate(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("BAP_CISO_TOKEN", "")
	t.Setenv("BAP_ADMIN_TOKEN", "")
	t.Setenv("BAP_DEV_MODE", "")
	t.Setenv("BAP_DEV_OVERRIDE", "")
	t.Setenv("BAP_ENVIRONMENT", "development")
}

func TestDevOverrideSkipsClientGrantChecks(t *testing.T) {
	original := AllowDevOverrides
	t.Cleanup(func() { AllowDevOverrides = original })
	for _, tc := range []struct {
		name, environment, buildFlag string
		expiry                       time.Duration
		wantEnforce                  bool
	}{
		{"active", "development", "true", time.Hour, false},
		{"expired", "development", "true", -time.Hour, true},
		{"production", "production", "true", time.Hour, true},
		{"release", "development", "false", time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolate(t)
			AllowDevOverrides = tc.buildFlag
			t.Setenv("BAP_ENVIRONMENT", tc.environment)
			t.Setenv("BAP_ZSP", "enforce")
			t.Setenv("BAP_DEV_OVERRIDE", time.Now().Add(tc.expiry).UTC().Format(time.RFC3339))
			if got := isZSPEnforcedClientSide(); got != tc.wantEnforce {
				t.Fatalf("client grant enforcement=%v, want=%v", got, tc.wantEnforce)
			}
			if !tc.wantEnforce {
				if allowed, reason, suggestion := evaluateNativeToolWithBapedge("sess-no-grants", "claude-code", "Read", "README.md"); !allowed || reason != "" || suggestion != "" {
					t.Fatalf("override requested a grant: allowed=%v reason=%q suggestion=%q", allowed, reason, suggestion)
				}
			}
		})
	}
}

func TestDevOverrideActive(t *testing.T) {
	in := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"unset", "", false},
		{"garbage", "maybe", false},
		{"valid RFC3339 window", in(time.Hour), true},
		{"expired RFC3339 window", in(-time.Minute), false},
		{"duration", "30m", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolate(t)
			t.Setenv("BAP_DEV_OVERRIDE", tc.value)
			if got, _ := devOverrideActive(); got != tc.want {
				t.Fatalf("devOverrideActive() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDevOverrideRequiresAdminTokenWhenConfigured(t *testing.T) {
	isolate(t)
	t.Setenv("BAP_CISO_TOKEN", "s3cret")
	t.Setenv("BAP_DEV_OVERRIDE", "30m")
	t.Setenv("BAP_ADMIN_TOKEN", "wrong")
	if got, _ := devOverrideActive(); got {
		t.Fatal("override must not activate with a mismatched admin token")
	}
	t.Setenv("BAP_ADMIN_TOKEN", "s3cret")
	if got, _ := devOverrideActive(); !got {
		t.Fatal("override should activate with the matching admin token")
	}
}

func TestLastAssistantTextSkipsToolResults(t *testing.T) {
	path := t.TempDir() + "/t.jsonl"
	lines := `{"type":"user","message":{"content":"first prompt"}}
{"type":"assistant","message":{"content":[{"type":"text","text":"old reply"}]}}
{"type":"user","message":{"content":"second prompt"}}
{"type":"assistant","message":{"content":[{"type":"text","text":"part one"},{"type":"tool_use","name":"Bash"}]}}
{"type":"user","message":{"content":[{"type":"tool_result","content":"ok"}]}}
{"type":"assistant","message":{"content":[{"type":"text","text":"part two"}]}}
`
	if err := os.WriteFile(path, []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}
	if got := lastAssistantText(path); got != "part one\n\npart two" {
		t.Fatalf("lastAssistantText = %q", got)
	}
}
