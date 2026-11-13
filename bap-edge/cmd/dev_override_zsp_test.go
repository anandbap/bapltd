package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-edge/pkg/version"
)

func TestDevOverrideTaskGrantEnforcement(t *testing.T) {
	// Keep developer markers and identity state isolated from the workstation.
	root := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("BAP_WORKSPACE_ROOT", root)
	t.Setenv("BAP_ZSP_DIR", filepath.Join(root, "zsp"))
	t.Setenv("BAP_ZSP", "enforce")
	t.Setenv("BAP_DEV_OVERRIDE", "")
	t.Setenv("BAP_DEV_MODE", "")
	originalBuildFlag := version.AllowDevOverrides
	t.Cleanup(func() { version.AllowDevOverrides = originalBuildFlag })

	for _, tc := range []struct {
		name        string
		environment string
		buildFlag   string
		active      bool
		expiry      time.Time
		wantEnforce bool
	}{
		{"inactive", "development", "true", false, time.Now().Add(time.Hour), true},
		{"active", "development", "true", true, time.Now().Add(time.Hour), false},
		{"expired", "development", "true", true, time.Now().Add(-time.Hour), true},
		{"production", "production", "true", true, time.Now().Add(time.Hour), true},
		{"release", "development", "false", true, time.Now().Add(time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BAP_ENVIRONMENT", tc.environment)
			version.AllowDevOverrides = tc.buildFlag
			marker, err := json.Marshal(devOverrideFile{Active: tc.active, ExpiresAt: tc.expiry})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile("dev-override.json", marker, 0600); err != nil {
				t.Fatal(err)
			}
			if got := taskGrantsEnforced(); got != tc.wantEnforce {
				t.Fatalf("taskGrantsEnforced() = %v, want %v", got, tc.wantEnforce)
			}
			for _, tool := range []struct{ name, command, path string }{
				{"PowerShell", "git status --short", ""},
				{"Read", "", filepath.Join(root, "README.md")},
			} {
				resp := evaluateWithBapedgeTool("sess-dev-bootstrap-"+tc.name, "codex", tool.name, tool.command, tool.path)
				if resp.Allowed == tc.wantEnforce {
					t.Fatalf("%s: allowed=%v, reason=%q, want task-grant enforcement=%v", tool.name, resp.Allowed, resp.Reason, tc.wantEnforce)
				}
				if tc.wantEnforce && !strings.Contains(resp.Reason, "ZeroStandingPrivilegeViolation") {
					t.Fatalf("expected task-grant denial, got %q", resp.Reason)
				}
			}
			if !tc.wantEnforce {
				// The bootstrap exemption must not bypass other tool boundaries.
				resp := evaluateWithBapedgeTool("sess-dev-bootstrap-root", "codex", "Read", "", string(os.PathSeparator))
				if resp.Allowed || !strings.Contains(resp.Reason, "Security Invariant Violation") {
					t.Fatalf("expected filesystem-root denial during override, got %+v", resp)
				}
			}
		})
	}
}
