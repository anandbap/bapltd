package main

import "strings"

// Keep the originating shell in both broker precheck and rewritten execution.
func brokerShellForTool(tool string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "bash", "sh", "zsh", "powershell", "pwsh", "cmd":
		return strings.ToLower(strings.TrimSpace(tool))
	case "cmd.exe":
		return "cmd"
	}
	return "auto"
}

func brokerShellFlag(tool string) string {
	if shell := brokerShellForTool(tool); shell != "auto" {
		return " --shell " + shell
	}
	return ""
}
