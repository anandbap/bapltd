package adapters

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CursorAdapter governs AI interactions within Cursor IDE environments
type CursorAdapter struct {
	WorkspaceRoot   string
	ControlPlaneURL string
	SessionID       string
	AgentID         string
}

// NewCursorAdapter creates a new CursorAdapter instance
func NewCursorAdapter(workspaceRoot, controlPlaneURL, sessionID, agentID string) *CursorAdapter {
	if sessionID == "" {
		sessionID = "sess-cursor-default"
	}
	if agentID == "" {
		agentID = "cursor-ide-agent"
	}
	return &CursorAdapter{
		WorkspaceRoot:   workspaceRoot,
		ControlPlaneURL: controlPlaneURL,
		SessionID:       sessionID,
		AgentID:         agentID,
	}
}

// ConfigureWorkspace writes zero-trust rules (.cursorrules) and MCP configuration (.cursor/mcp.json)
func (a *CursorAdapter) ConfigureWorkspace() error {
	cursorDir := filepath.Join(a.WorkspaceRoot, ".cursor")
	if err := os.MkdirAll(cursorDir, 0755); err != nil {
		return err
	}

	// 1. Write .cursorrules
	cursorRulesPath := filepath.Join(a.WorkspaceRoot, ".cursorrules")
	rulesContent := `# BAP Zero-Trust Policy & Shell Governance for Cursor IDE
All terminal and shell executions MUST run strictly through bapedge.exe exec:
  bapedge.exe exec "<command>"
Direct, ungoverned shell execution is strictly blocked by enterprise security invariants.
`
	if err := os.WriteFile(cursorRulesPath, []byte(rulesContent), 0644); err != nil {
		return fmt.Errorf("failed to write .cursorrules: %w", err)
	}

	// 2. Write .cursor/mcp.json
	mcpConfigPath := filepath.Join(cursorDir, "mcp.json")
	mcpConfig := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"bap-zero-trust": map[string]interface{}{
				"command": "bapmcp.exe",
				"args":    []string{"serve"},
			},
		},
	}
	data, err := json.MarshalIndent(mcpConfig, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(mcpConfigPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write .cursor/mcp.json: %w", err)
	}

	return nil
}

// InterceptActivity evaluates and records Cursor tool/terminal activity
func (a *CursorAdapter) InterceptActivity(activityType, target string) (*CanonicalActivityEvent, error) {
	decision := "ALLOW"
	reason := "Governed Cursor execution broker"

	// Basic safety check for dangerous direct executions
	lower := strings.ToLower(target)
	if strings.Contains(lower, "format c:") || strings.Contains(lower, "rmdir /s /q c:\\") || strings.Contains(lower, "rm -rf /") {
		decision = "DENY"
		reason = "Malicious or destructive command pattern detected"
	}

	event := NewActivityEvent("cursor", a.SessionID, a.AgentID, activityType, target, decision, reason)
	event.Metadata["workspace"] = a.WorkspaceRoot

	_ = ReportActivity(a.ControlPlaneURL, event)
	return event, nil
}
