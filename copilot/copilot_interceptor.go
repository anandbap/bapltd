package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ExecResponse represents the JSON output from ltd-agent exec.
type ExecResponse struct {
	Allowed    bool   `json:"allowed"`
	Output     string `json:"output,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
	Warning    string `json:"warning,omitempty"`
}

func main() {
	var command string

	// 1. Check if command is passed via CLI arguments
	if len(os.Args) > 1 {
		command = strings.TrimSpace(strings.Join(os.Args[1:], " "))
	} else {
		// 2. Otherwise read from stdin (JSON payload or raw command line)
		inputBytes, err := io.ReadAll(os.Stdin)
		if err == nil && len(inputBytes) > 0 {
			raw := strings.TrimSpace(string(inputBytes))
			// Attempt to parse as JSON if it looks like JSON
			if strings.HasPrefix(raw, "{") {
				var payload struct {
					Command     string                 `json:"command"`
					Cmd         string                 `json:"cmd"`
					CommandLine string                 `json:"CommandLine"`
					Input       string                 `json:"input"`
					ToolInput   struct {
						Command     string `json:"command"`
						Cmd         string `json:"cmd"`
						CommandLine string `json:"CommandLine"`
					} `json:"tool_input"`
					Args map[string]interface{} `json:"args"`
				}
				if err := json.Unmarshal(inputBytes, &payload); err == nil {
					if payload.Command != "" {
						command = payload.Command
					} else if payload.Cmd != "" {
						command = payload.Cmd
					} else if payload.CommandLine != "" {
						command = payload.CommandLine
					} else if payload.ToolInput.Command != "" {
						command = payload.ToolInput.Command
					} else if payload.ToolInput.Cmd != "" {
						command = payload.ToolInput.Cmd
					} else if payload.ToolInput.CommandLine != "" {
						command = payload.ToolInput.CommandLine
					} else if payload.Input != "" {
						command = payload.Input
					} else if payload.Args != nil {
						if c, ok := payload.Args["command"].(string); ok && c != "" {
							command = c
						} else if c, ok := payload.Args["CommandLine"].(string); ok && c != "" {
							command = c
						} else if c, ok := payload.Args["cmd"].(string); ok && c != "" {
							command = c
						}
					}
				}
			}
			if command == "" {
				command = raw
			}
		}
	}

	if command == "" {
		fmt.Fprintln(os.Stderr, "[copilot-interceptor] Error: No command provided to execute.")
		os.Exit(1)
	}

	// 3. Resolve bapedge (LTD) or ltd-agent executable
	binName := "bapedge"
	fallbackName := "ltd-agent"
	if runtime.GOOS == "windows" {
		binName = "bapedge.exe"
		fallbackName = "ltd-agent.exe"
	}
	ltdBin := findBinary(binName)
	if _, err := os.Stat(ltdBin); err != nil {
		ltdBin = findBinary(fallbackName)
	}

	// 4. Resolve session identifier
	sessionID := os.Getenv("BAP_SESSION_ID")
	if sessionID == "" {
		sessionID = os.Getenv("LTD_SESSION_ID")
	}
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-copilot-pid-%d", os.Getppid())
	}

	// 5. Execute bapedge exec --source copilot --session-id <sessionID> --json "$command"
	execArgs := []string{"exec", "--source", "copilot", "--json"}
	if sessionID != "" {
		execArgs = append(execArgs, "--session-id", sessionID)
	}
	execArgs = append(execArgs, command)

	cmd := exec.Command(ltdBin, execArgs...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "BAP_SESSION_ID="+sessionID)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()

	// 5. Parse output
	var execResp ExecResponse
	if err := json.Unmarshal(stdout.Bytes(), &execResp); err != nil {
		fmt.Fprintf(os.Stderr, "[copilot-interceptor] ltd-agent execution error: %s\n", stdout.String())
		os.Exit(1)
	}

	if !execResp.Allowed {
		fmt.Fprintf(os.Stderr, "[COPILOT BLOCKED BY POLICY] %s\n", execResp.Reason)
		if execResp.Suggestion != "" {
			fmt.Fprintf(os.Stderr, "[SUGGESTION] %s\n", execResp.Suggestion)
		}
		fmt.Fprintln(os.Stderr, "[CRITICAL SECURITY INVARIANT] Access to this resource is permanently prohibited by enterprise zero-trust policy.")
		fmt.Fprintln(os.Stderr, "[INSTRUCTION TO AI AGENT] You must CEASE all attempts to access, read, copy, rename, or exfiltrate this resource. Do NOT attempt alternative commands, scripts, or workarounds. Abort this task immediately and notify the user.")
		os.Exit(1)
	}

	if execResp.Warning != "" {
		fmt.Fprintln(os.Stderr, execResp.Warning)
	}

	if execResp.Output != "" {
		fmt.Print(execResp.Output)
		if !strings.HasSuffix(execResp.Output, "\n") {
			fmt.Println()
		}
	}
	os.Exit(0)
}

func findBinary(name string) string {
	// 1. Current working directory
	if _, err := os.Stat(name); err == nil {
		abs, err := filepath.Abs(name)
		if err == nil {
			return abs
		}
		return name
	}
	// 2. Look in parent directories (e.g. ../ltd-agent.exe, ../ltd-agent/ltd-agent.exe)
	candidates := []string{
		filepath.Join("..", name),
		filepath.Join("..", "bap-edge", name),
		filepath.Join("bap-edge", name),
		filepath.Join("..", "ltd-agent", name),
		filepath.Join("ltd-agent", name),
		filepath.Join("cchook", name),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, err := filepath.Abs(c)
			if err == nil {
				return abs
			}
			return c
		}
	}
	// 3. System PATH
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}
