package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"bap-edge/internal/audit"
)

// Fallback request reporting (Layer 2).
//
// When Layer 1 hooks are not reporting (unapproved, disabled or stale), the agent can
// call bap_report_request once per user turn. The record is graded self_reported: it is
// the model's own account, never verified, and is never used for policy decisions.
// If a hook ran for the session recently the call is dropped so nothing is double counted.
// The tool is only exposed when BAP_FALLBACK_REPORTING=1.

const (
	hookGraceWindow    = 30 * time.Second
	maxReportSummary   = 2048
	reportRequestTool  = "bap_report_request"
	fallbackFlagEnvVar = "BAP_FALLBACK_REPORTING"
)

func fallbackReportingEnabled() bool {
	return os.Getenv(fallbackFlagEnvVar) == "1"
}

var (
	reportedTurnsMu sync.Mutex
	reportedTurns   = map[string]struct{}{}
)

// emitReport is replaced in tests.
var emitReport = func(entry audit.AuditEntry, cfg ServerConfig) {
	_ = audit.Log(&entry, cfg.AuditLogPath)
	_, _, _ = audit.Transmit(entry, cfg.ServerURL, cfg.AuditLogPath)
}

func reportRequestToolDef() Tool {
	return Tool{
		Name: reportRequestTool,
		Description: "Report, once per user turn, a short summary of what the user just asked you to do. " +
			"This is a fallback audit record used only when the host's native hooks are not reporting. " +
			"It is self-reported and is ignored if hooks already recorded the turn.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"request_summary": map[string]string{"type": "string", "description": "Short summary of the user's request (max 2048 chars)"},
				"turn_id":         map[string]string{"type": "string", "description": "Identifier for this user turn; reuse the same value if you report the same turn again"},
				"session_id":      map[string]string{"type": "string", "description": "Optional agent session id"},
			},
			Required: []string{"request_summary"},
		},
	}
}

// hookStateDirForMCP mirrors cchook.hookStateDir so both sides use the same location.
func hookStateDirForMCP() string {
	if dir := strings.TrimSpace(os.Getenv("BAP_STATE_DIR")); dir != "" {
		return dir
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "bin", ".bapstate")
	}
	return filepath.Join(os.TempDir(), "bapstate")
}

// hookHeartbeatFile mirrors cchook.hookHeartbeatName.
func hookHeartbeatFile(sessionID string) string {
	var b strings.Builder
	for _, r := range sessionID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	name := b.String()
	if len(name) > 120 {
		name = name[:120]
	}
	return name
}

// hookRecentlyActive reports whether a hook touched the session heartbeat within grace.
func hookRecentlyActive(stateDir, sessionID string, grace time.Duration, now time.Time) bool {
	name := hookHeartbeatFile(sessionID)
	if name == "" || name == "." || name == ".." {
		return false
	}
	fi, err := os.Stat(filepath.Join(stateDir, "hook-heartbeat", name))
	if err != nil {
		return false
	}
	age := now.Sub(fi.ModTime())
	return age <= grace && age > -grace
}

func reportResult(recorded bool, reason string) CallToolResult {
	body, _ := json.Marshal(map[string]interface{}{
		"recorded":       recorded,
		"reason":         reason,
		"evidence_grade": "self_reported",
	})
	return CallToolResult{Content: []ContentBlock{{Type: "text", Text: string(body)}}}
}

func handleReportRequest(args map[string]interface{}, cfg ServerConfig) CallToolResult {
	return reportRequest(args, cfg, hookStateDirForMCP(), time.Now())
}

func reportRequest(args map[string]interface{}, cfg ServerConfig, stateDir string, now time.Time) CallToolResult {
	if !fallbackReportingEnabled() {
		return reportResult(false, "fallback_reporting_disabled")
	}
	summary, _ := args["request_summary"].(string)
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: "Parameter 'request_summary' is required"}},
			IsError: true,
		}
	}
	if len(summary) > maxReportSummary {
		summary = summary[:maxReportSummary]
	}

	sessionID := cfg.SessionID
	if sessionID == "" {
		if s, _ := args["session_id"].(string); s != "" {
			sessionID = s
		}
	}
	if sessionID == "" {
		sessionID = "sess-mcp-" + strconv.Itoa(os.Getpid())
	}

	// Layer 1 is reporting for this session: do not duplicate its record.
	if hookRecentlyActive(stateDir, sessionID, hookGraceWindow, now) {
		return reportResult(false, "hook_active")
	}

	turnID, _ := args["turn_id"].(string)
	turnID = strings.TrimSpace(turnID)
	if turnID == "" {
		sum := sha256.Sum256([]byte(summary))
		turnID = "turn-" + hex.EncodeToString(sum[:6])
	}
	key := sessionID + "\x00" + turnID
	reportedTurnsMu.Lock()
	_, dup := reportedTurns[key]
	if !dup {
		reportedTurns[key] = struct{}{}
	}
	reportedTurnsMu.Unlock()
	if dup {
		return reportResult(false, "duplicate_turn")
	}

	var uID, uEmail, spiffeID string
	if cfg.IdentityResolver != nil {
		uID, uEmail, spiffeID = cfg.IdentityResolver()
	}
	entry := audit.AuditEntry{
		ReportingLayer: "mcp",
		EvidenceGrade:  "self_reported",
		TurnID:         turnID,
		SessionID:      sessionID,
		UserID:         uID,
		UserEmail:      uEmail,
		SPIFFEID:       spiffeID,
		Timestamp:      now.UTC(),
		Source:         "mcp-self-report",
		ClientPID:      os.Getpid(),
		Executable:     "user_prompt",
		UserPrompt:     summary,
		Decision:       "observed",
	}
	emitReport(entry, cfg)
	return reportResult(true, "recorded")
}
