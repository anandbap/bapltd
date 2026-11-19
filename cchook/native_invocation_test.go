package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeDigestIncludesWriteContentAndCanonicalizesInput(t *testing.T) {
	a := nativeInputDigest([]byte(`{"tool_input":{"file_path":"pilot_check.py","content":"print(1)"}}`))
	b := nativeInputDigest([]byte(`{"toolInput":{"content":"print(1)","file_path":"pilot_check.py"}}`))
	c := nativeInputDigest([]byte(`{"tool_input":{"file_path":"pilot_check.py","content":"print(2)"}}`))
	if a == "" || a != b || a == c { t.Fatal("native digest discarded content or depended on key ordering") }
}

func TestNativeWritePluginAndStandaloneShareSingleUse(t *testing.T) {
	source, broker, interceptor := setupZSPHookTestEnv(t)
	ws := t.TempDir()
	for _, name := range []string{"policy.cedar", "schema.json"} {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil { t.Fatal(err) }
		if err := os.WriteFile(filepath.Join(ws, name), data, 0600); err != nil { t.Fatal(err) }
	}
	t.Setenv("BAP_WORKSPACE_ROOT", ws)
	t.Setenv("BAP_SERVER_URL", "http://127.0.0.1:1")
	const session = "native-duplicate-regression"
	t.Setenv("BAP_SESSION_ID", session)
	liveness := watcherLivenessPath(session)
	if err := os.MkdirAll(filepath.Dir(liveness), 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(liveness, []byte("fixture"), 0600); err != nil { t.Fatal(err) }
	grant := exec.Command(broker, "zsp", "authorize", "--session-id", session, "--mission", "TASK_EXECUTION", "--goal", "write pilot", "--actions", "fs:file:write", "--resources", "workspace://current", "--max-uses", "1")
	grant.Dir = ws
	if out, err := grant.CombinedOutput(); err != nil { t.Fatalf("grant: %v %s", err, out) }
	run := func(plugin bool, event, id, content string) map[string]any {
		t.Helper()
		hostSession := "host-session-overridden-by-launcher"
		payload, _ := json.Marshal(map[string]any{"hook_event_name": event, "app_id": "claude-code", "session_id": hostSession, "tool_name": "Write", "tool_use_id": id, "tool_input": map[string]any{"file_path": "pilot_check.py", "content": content}})
		cmd := exec.Command(interceptor)
		if plugin { cmd = exec.Command(broker, "plugin", "adapter", "--client", "claude-code", "--event", event) }
		cmd.Dir, cmd.Stdin = ws, bytes.NewReader(payload)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil { t.Fatalf("callback: %v %s %s", err, out, stderr.String()) }
		var response map[string]any
		if err := json.Unmarshal(out, &response); err != nil { t.Fatalf("callback JSON: %v %s", err, out) }
		return response
	}
	assertDecision := func(response map[string]any, expected string) {
		t.Helper()
		hook, ok := response["hookSpecificOutput"].(map[string]any)
		if !ok || hook["permissionDecision"] != expected { t.Fatalf("want %s, got %+v", expected, response) }
	}
	assertDecision(run(true, "PreToolUse", "one", "print(1)"), "allow")
	assertDecision(run(false, "PreToolUse", "one", "print(1)"), "allow")
	assertDecision(run(false, "PreToolUse", "one", "print(1)"), "allow")
	assertDecision(run(true, "PreToolUse", "one", "print(2)"), "deny")
	assertDecision(run(false, "PreToolUse", "two", "print(1)"), "deny")
	run(false, "PostToolUseFailure", "one", "print(1)")
	assertDecision(run(true, "PreToolUse", "one", "print(1)"), "deny")
	if _, err := os.Stat(filepath.Join(ws, "pilot_check.py")); !os.IsNotExist(err) { t.Fatal("prechecks executed a native write") }
}
