package adapters

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GeminiCLIAdapter governs AI interactions within Gemini CLI / Google AI developer sessions
type GeminiCLIAdapter struct {
	WorkspaceRoot   string
	ControlPlaneURL string
	SessionID       string
	AgentID         string
}

// NewGeminiCLIAdapter creates a new GeminiCLIAdapter instance
func NewGeminiCLIAdapter(workspaceRoot, controlPlaneURL, sessionID, agentID string) *GeminiCLIAdapter {
	if sessionID == "" {
		sessionID = "sess-gemini-cli-default"
	}
	if agentID == "" {
		agentID = "gemini-cli-agent"
	}
	return &GeminiCLIAdapter{
		WorkspaceRoot:   workspaceRoot,
		ControlPlaneURL: controlPlaneURL,
		SessionID:       sessionID,
		AgentID:         agentID,
	}
}

// ConfigureWorkspace writes zero-trust mission invariants to GEMINI.md
func (a *GeminiCLIAdapter) ConfigureWorkspace() error {
	geminiPath := filepath.Join(a.WorkspaceRoot, "GEMINI.md")
	content := fmt.Sprintf(`# BAP Zero-Trust Policy & Shell Governance for Gemini CLI (Governed Session: %s)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Mandatory Execution Rules
1. All shell executions MUST run through bapedge.exe exec:
   bapedge.exe exec "<command>"
2. Commands are evaluated against Cedar invariants before execution.
`, a.SessionID)

	if err := os.WriteFile(geminiPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write GEMINI.md: %w", err)
	}
	return nil
}

// InterceptActivity evaluates and records Gemini CLI tool/terminal activity
func (a *GeminiCLIAdapter) InterceptActivity(activityType, target string) (*CanonicalActivityEvent, error) {
	decision := "ALLOW"
	reason := "Governed Gemini CLI execution broker"

	lower := strings.ToLower(target)
	if strings.Contains(lower, "drop database") || strings.Contains(lower, "format ") || strings.Contains(lower, "rm -rf /") {
		decision = "DENY"
		reason = "Prohibited destructive operation"
	}

	event := NewActivityEvent("gemini-cli", a.SessionID, a.AgentID, activityType, target, decision, reason)
	event.Metadata["workspace"] = a.WorkspaceRoot

	_ = ReportActivity(a.ControlPlaneURL, event)
	return event, nil
}
