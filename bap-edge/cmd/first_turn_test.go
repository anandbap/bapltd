package cmd

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"bap-edge/internal/sandbox"
)

func TestPluginStartupAndPromptAgreeOnGrantMode(t *testing.T) {
	for _, auto := range []string{"0", "1"} {
		t.Setenv("BAP_ZSP_AUTO_GRANTS", auto)
		for _, event := range []string{"SessionStart", "UserPromptSubmit"} {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			old := os.Stdout
			os.Stdout = w
			emitPluginZSPContext(event, "fresh-session")
			w.Close()
			os.Stdout = old
			out, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			var body struct {
				Hook struct {
					Event   string `json:"hookEventName"`
					Context string `json:"additionalContext"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal(out, &body); err != nil {
				t.Fatal(err)
			}
			if body.Hook.Event != event || !strings.Contains(body.Hook.Context, "fresh-session") {
				t.Fatalf("invalid context: %s", out)
			}
			if strings.Contains(body.Hook.Context, "Submit routine command batches normally") != (auto == "1") {
				t.Fatalf("plugin instructs wrong grant mode: %s", out)
			}
		}
	}
}

func TestPluginRecognizesExplicitShellTools(t *testing.T) {
	for _, tool := range []string{"Bash", "sh", "zsh", "PowerShell", "pwsh", "cmd"} {
		if sandbox.ToolShell(tool) != strings.ToLower(tool) {
			t.Fatalf("lost tool shell %s", tool)
		}
	}
}
