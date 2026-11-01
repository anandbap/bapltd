package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeMCPDiscoveryAttemptAndOutcome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("BAP_STATE_DIR", root)
	payload := HookPayload{SessionID: "native-session", ToolName: "mcp__filesystem__read_file", ToolUseID: "tool-123", Source: "claude-code", ToolInput: ToolInput{Path: "SYNTHETIC-PRIVATE-INPUT"}}
	for _, outcome := range []string{"attempted", "succeeded", "failed", "denied"} {
		if err := spoolMCPObservation(payload, outcome); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.ReadDir(filepath.Join(root, "discovery", "pending"))
	if err != nil || len(files) != 4 {
		t.Fatal(files, err)
	}
	operation := ""
	for _, file := range files {
		raw, _ := os.ReadFile(filepath.Join(root, "discovery", "pending", file.Name()))
		if strings.Contains(string(raw), "SYNTHETIC-PRIVATE-INPUT") {
			t.Fatal("MCP input leaked")
		}
		var report struct {
			Observations []struct {
				OperationID string `json:"operation_id"`
				Evidence    string `json:"evidence"`
			}
		}
		json.Unmarshal(raw, &report)
		if len(report.Observations) != 1 || report.Observations[0].Evidence != "invocation" {
			t.Fatal(string(raw))
		}
		id := report.Observations[0].OperationID
		if operation != "" && id != operation {
			t.Fatal("outcome correlation changed")
		}
		operation = id
	}
	payload.ToolUseID = ""
	if err := spoolMCPObservation(payload, "attempted"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadDir(filepath.Join(root, "discovery", "pending"))
	if len(after) != 4 {
		t.Fatal("invented tool correlation")
	}
}

func TestPostToolCallbackNeverRunsPreToolChecks(t *testing.T) {
	root := t.TempDir()
	t.Setenv("BAP_STATE_DIR", root)
	input, err := os.CreateTemp(root, "payload-")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	// A pre-tool path would reject this synthetic credential path. The post
	// callback must record its outcome and return an empty non-decision object.
	_, _ = input.WriteString(`{"hook_event_name":"PostToolUseFailure","session_id":"post-session","tool_use_id":"post-tool","tool_name":"mcp__fixture__read","tool_input":{"file_path":".env","command":"never execute this"}}`)
	_, _ = input.Seek(0, 0)
	output, err := os.CreateTemp(root, "output-")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stdin, stdout, style, caller := os.Stdin, os.Stdout, activeDecisionStyle, activeCallerAppID
	os.Stdin, os.Stdout = input, output
	defer func() { os.Stdin, os.Stdout, activeDecisionStyle, activeCallerAppID = stdin, stdout, style, caller }()
	main()
	_, _ = output.Seek(0, 0)
	raw := make([]byte, 256)
	n, _ := output.Read(raw)
	if strings.TrimSpace(string(raw[:n])) != "{}" {
		t.Fatalf("post callback emitted a pre-tool decision: %s", raw[:n])
	}
	files, _ := os.ReadDir(filepath.Join(root, "discovery", "pending"))
	if len(files) != 1 {
		t.Fatal("post evidence missing")
	}
	body, _ := os.ReadFile(filepath.Join(root, "discovery", "pending", files[0].Name()))
	if !strings.Contains(string(body), `"outcome":"failed"`) || strings.Contains(string(body), "never execute") {
		t.Fatal("incorrect post outcome or leaked input")
	}
}
