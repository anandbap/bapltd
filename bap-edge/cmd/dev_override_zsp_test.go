package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-edge/pkg/types"
	"bap-edge/pkg/version"
)

func TestDevOverrideExecHelper(t *testing.T) {
	if os.Getenv("BAP_TEST_OVERRIDE_EXEC_HELPER") != "1" {
		return
	}
	version.AllowDevOverrides = os.Getenv("BAP_TEST_OVERRIDE_BUILD_FLAG")
	// The Windows package TestMain replaces BAP_STATE_DIR; restore this child
	// fixture's explicit state directory before exercising the broker.
	_ = os.Setenv("BAP_STATE_DIR", os.Getenv("BAP_TEST_OVERRIDE_STATE_DIR"))
	for i, arg := range os.Args {
		if arg == "--" {
			RunExec(os.Args[i+1:])
			os.Exit(99)
		}
	}
	t.Fatal("missing broker arguments")
}

func TestDevOverrideExecWithoutGrants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, environment, buildFlag string
		active                       bool
	}{
		{"active", "development", "true", true},
		{"active-bin-state", "development", "true", true},
		{"active-custom-state", "development", "true", true},
		{"inactive", "development", "true", false},
		{"production", "production", "true", true},
		{"release", "development", "false", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"policy.cedar", "schema.json"} {
				data, err := os.ReadFile(filepath.Join("..", "..", name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			marker, _ := json.Marshal(devOverrideFile{Active: tc.active, ExpiresAt: time.Now().Add(time.Hour)})
			markerDir := root
			if tc.name == "active-bin-state" {
				markerDir = filepath.Join(root, "bin", ".bapstate")
			}
			if tc.name == "active-custom-state" {
				markerDir = filepath.Join(root, "state")
			}
			if err := os.MkdirAll(markerDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(markerDir, "dev-override.json"), marker, 0600); err != nil {
				t.Fatal(err)
			}
			for key, value := range map[string]string{
				"BAP_TEST_OVERRIDE_EXEC_HELPER": "1", "BAP_TEST_OVERRIDE_BUILD_FLAG": tc.buildFlag,
				"BAP_ENVIRONMENT": tc.environment, "BAP_WORKSPACE_ROOT": root,
				"HOME": root, "USERPROFILE": root, "BAP_ZSP": "enforce",
				"BAP_ZSP_DIR": filepath.Join(root, "zsp"), "BAP_STATE_DIR": filepath.Join(root, "state"),
				"BAP_TEST_OVERRIDE_STATE_DIR": filepath.Join(root, "state"),
				"BAP_SERVER_URL":              server.URL, "BAP_CONTROLPLANE_URL": server.URL,
				"BAP_DEV_OVERRIDE": "", "BAP_DEV_MODE": "", "BAP_NON_INTERACTIVE": "1",
			} {
				t.Setenv(key, value)
			}
			// Exercise authorization independently of host sandbox availability.
			for _, toolArgs := range [][]string{{"--decision-only", "echo override-without-grant"}, {"--tool", "Read", "--target", filepath.Join(root, "README.md"), "--consume"}} {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				args := []string{"-test.run=^TestDevOverrideExecHelper$", "--", "--json", "--mode", "enforce", "--server", server.URL, "--source", "copilot", "--session-id", "sess-no-grants"}
				cmd := exec.CommandContext(ctx, self, append(args, toolArgs...)...)
				cmd.Dir = root
				cmd.WaitDelay = time.Second
				var stderr strings.Builder
				cmd.Stderr = &stderr
				output, runErr := cmd.Output()
				var resp types.ExecResponse
				if err := json.Unmarshal(output, &resp); err != nil {
					t.Fatalf("broker response: %v, output=%s stderr=%s run=%v", err, output, stderr.String(), runErr)
				}
				wantAllow := tc.active && tc.environment == "development" && tc.buildFlag == "true"
				if resp.Allowed != wantAllow {
					t.Fatalf("allowed=%v, want=%v: %s stderr=%s", resp.Allowed, wantAllow, output, stderr.String())
				}
				if wantAllow {
					if runErr != nil || resp.Suggestion != "" || (resp.Receipt != nil && resp.Receipt.GrantID != "") {
						t.Fatalf("override must execute without a grant or prompt: %s run=%v", output, runErr)
					}
				} else if !strings.Contains(resp.Reason, "ZeroStandingPrivilegeViolation") {
					t.Fatalf("expected grant enforcement: %s", output)
				}
			}
		})
	}
}

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
