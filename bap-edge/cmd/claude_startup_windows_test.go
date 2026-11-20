//go:build windows

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
)

func TestClaudeNpmShimPreservesJSONArguments(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "node_modules", "@anthropic-ai", "claude-code")
	if err := os.MkdirAll(pkg, 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"package.json": `{"bin":{"claude":"cli.js"}}`, "cli.js": `process.stdout.write(JSON.stringify(process.argv.slice(2)))`} {
		if err := os.WriteFile(filepath.Join(pkg, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	settings := `{"path":"C:\\work space\\hooks","prompt":"a & b %PATH% ! quote\""}`
	command, err := claudeCLICommand(context.Background(), filepath.Join(root, "claude.cmd"), "--settings", settings)
	if err != nil {
		t.Fatal(err)
	}
	out, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal(out, &args); err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[0] != "--settings" || args[1] != settings {
		t.Fatalf("arguments changed: %s", out)
	}
}

func runClaudeStartupFixture() bool {
	if os.Getenv("BAP_CLAUDE_STARTUP_FIXTURE") != "1" {
		return false
	}
	for _, arg := range os.Args[1:] {
		if arg == "--help" {
			fmt.Println("--settings --setting-sources")
			os.Exit(0)
		}
	}
	for i, arg := range os.Args[1:] {
		if arg == "--settings" && i+2 < len(os.Args) {
			raw := []byte(os.Args[i+2])
			if !json.Valid(raw) {
				fmt.Fprintln(os.Stderr, "invalid settings received by child")
				os.Exit(2)
			}
			if err := os.WriteFile(os.Getenv("BAP_CLAUDE_STARTUP_OUTPUT"), raw, 0600); err != nil {
				os.Exit(3)
			}
			os.Exit(0)
		}
	}
	os.Exit(4)
	return true
}

func TestClaudeLaunchesChildWithDuplicateHooksAndUserPreferences(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	home := filepath.Join(root, "home")
	for _, dir := range []string{workspace, filepath.Join(home, ".claude")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(workspace)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
	t.Setenv("ProgramFiles", root)
	t.Setenv("BAP_STATE_DIR", filepath.Join(root, "state"))
	t.Setenv("BAP_TEST_ENV", "1")
	state.ResetForTesting()
	defer state.ResetForTesting()
	user := filepath.Join(home, ".claude", "settings.json")
	original := []byte(`{"autoUpdatesChannel":"stable","model":"user-model","hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"bapedge plugin adapter"},{"type":"command","command":"interceptor.exe"}]}]}}`)
	if err := os.WriteFile(user, original, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "child-started.json")
	t.Setenv("BAP_CLAUDE_STARTUP_FIXTURE", "1")
	t.Setenv("BAP_CLAUDE_STARTUP_OUTPUT", output)
	oldResolver := claudeExecutableResolver
	claudeExecutableResolver = func() string { return os.Args[0] }
	defer func() { claudeExecutableResolver = oldResolver }()
	oldTransport := httptransport.MockTransport
	httptransport.MockTransport = mockRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":"active"}`))}, nil
	})
	defer func() { httptransport.MockTransport = oldTransport }()
	if err := RunClaude([]string{"-p", "fixture prompt"}); err != nil {
		t.Fatal("Claude child was never started", err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal("no actual child startup marker", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["autoUpdatesChannel"] != "stable" || settings["model"] != "user-model" {
		t.Fatal("unrelated user settings lost", settings)
	}
	after, _ := os.ReadFile(user)
	if string(after) != string(original) {
		t.Fatal("original user settings modified")
	}
	entries, err := os.ReadDir(filepath.Join(workspace, ".bap", "claude-launches"))
	if err != nil || len(entries) != 0 {
		t.Fatal("launch left temporary artifacts", entries, err)
	}
}
