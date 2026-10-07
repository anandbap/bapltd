package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/authz"
	"bap-edge/internal/pinning"
	"bap-edge/internal/sandbox"
)

// MCP Protocol Constants
const (
	ProtocolVersion = "2024-11-05"
	ServerName      = "bap-zero-trust"
	ServerVersion   = "1.0.0"
)

// JSONRPCRequest represents an incoming JSON-RPC 2.0 message.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an outgoing JSON-RPC 2.0 message.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id,omitempty"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError defines the standard error structure.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ContentBlock is an MCP standard content element.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallToolResult defines tool execution results returned to the agent.
type CallToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

// Tool defines an MCP tool definition.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema defines JSON Schema for tool parameters.
type InputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Required   []string               `json:"required,omitempty"`
}

// ServerConfig configures the MCP server runtime.
type ServerConfig struct {
	PolicyPath       string
	ServerURL        string
	SessionID        string
	AuditLogPath     string
	EnforcementMode  string
	IdentityResolver func() (userID, userEmail, spiffeID string)
}

// StartServer runs the stdio JSON-RPC loop for the MCP server.
func StartServer(cfg ServerConfig) error {
	// Ensure log outputs go to stderr so stdout is purely JSON-RPC messages
	log.SetOutput(os.Stderr)

	authorizer, err := authz.NewAuthorizer(cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to initialize Cedar authorizer: %w", err)
	}

	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			sendError(writer, nil, -32700, "Parse error: "+err.Error())
			continue
		}

		handleRequest(writer, req, authorizer, cfg)
	}

	return nil
}

func handleRequest(w *bufio.Writer, req JSONRPCRequest, authorizer *authz.Authorizer, cfg ServerConfig) {
	// Handle notifications (no ID, no response required)
	if req.ID == nil && strings.HasPrefix(req.Method, "notifications/") {
		return
	}

	switch req.Method {
	case "initialize":
		result := map[string]interface{}{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]string{
				"name":    ServerName,
				"version": ServerVersion,
			},
		}
		sendResult(w, req.ID, result)

	case "ping":
		sendResult(w, req.ID, map[string]interface{}{})

	case "tools/list":
		tools := []Tool{
			{
				Name: "bap_execute",
				Description: "Executes a shell command inside the BAP Zero-Trust kernel sandbox. " +
					"Every command is strictly evaluated against enterprise Cedar security invariants before execution. " +
					"Injects authenticated corporate identity tokens and records immutable audit telemetry.",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"command": map[string]string{
							"type":        "string",
							"description": "The exact shell command line to execute (e.g. 'powershell ...', 'git status', 'python ...')",
						},
						"reason": map[string]string{
							"type":        "string",
							"description": "Optional developer rationale or agent task context for this command",
						},
					},
					Required: []string{"command"},
				},
			},
			{
				Name: "bap_explain_policy",
				Description: "Dry-runs a command against BAP Cedar authorization policies without executing it. " +
					"Returns whether the command would be permitted, the policy decision reason, and actionable remediation suggestions.",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"command": map[string]string{
							"type":        "string",
							"description": "The shell command to test for policy compliance",
						},
					},
					Required: []string{"command"},
				},
			},
			{
				Name: "bap_status",
				Description: "Returns the current BAP Zero-Trust edge agent status, SPIFFE ID, active session ID, " +
					"control plane connection state, and active security invariants.",
				InputSchema: InputSchema{
					Type:       "object",
					Properties: map[string]interface{}{},
				},
			},
		}
		sendResult(w, req.ID, map[string]interface{}{"tools": tools})

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			sendError(w, req.ID, -32602, "Invalid params: "+err.Error())
			return
		}

		// Pre-flight AIR Content Pinning check for MCP tools (BAP-531)
		manifest, _ := pinning.LoadManifest("")
		if manifest != nil && len(manifest.Assets) > 0 {
			toolKey := fmt.Sprintf("mcp:%s", params.Name)
			res := manifest.VerifyAsset(toolKey)
			if res.Asset.ID != "" && !res.Matches {
				sendToolError(w, req.ID, fmt.Sprintf("HashMismatchError: %s", res.Error))
				return
			}
		}

		switch params.Name {
		case "bap_execute":
			cmdVal, _ := params.Arguments["command"].(string)
			if strings.TrimSpace(cmdVal) == "" {
				sendToolError(w, req.ID, "Missing required argument 'command'")
				return
			}
			res := executeCommand(cmdVal, authorizer, cfg)
			sendResult(w, req.ID, res)

		case "bap_explain_policy":
			cmdVal, _ := params.Arguments["command"].(string)
			if strings.TrimSpace(cmdVal) == "" {
				sendToolError(w, req.ID, "Missing required argument 'command'")
				return
			}
			res := explainPolicy(cmdVal, authorizer)
			sendResult(w, req.ID, res)

		case "bap_status":
			res := getStatus(cfg)
			sendResult(w, req.ID, res)

		default:
			sendError(w, req.ID, -32601, fmt.Sprintf("Unknown tool: %s", params.Name))
		}

	default:
		sendError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func executeCommand(fullCommand string, authorizer *authz.Authorizer, cfg ServerConfig) CallToolResult {
	startTime := time.Now().UTC()
	cleaned := sandbox.CleanCommandString(fullCommand)
	executable, cmdArguments := sandbox.ParseCommand(cleaned)

	allowed, reason, err := authorizer.Evaluate(executable, cleaned, cmdArguments)
	if err != nil {
		return CallToolResult{
			Content: []ContentBlock{{
				Type: "text",
				Text: fmt.Sprintf("[ERROR] Cedar policy evaluation failed: %v", err),
			}},
			IsError: true,
		}
	}

	var uID, uEmail, spiffeID string
	if cfg.IdentityResolver != nil {
		uID, uEmail, spiffeID = cfg.IdentityResolver()
	}
	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-mcp-%d", os.Getpid())
	}

	isAudit := strings.EqualFold(cfg.EnforcementMode, "audit") || strings.EqualFold(cfg.EnforcementMode, "shadow")

	if !allowed {
		suggestion := GenerateSuggestion(cleaned, executable, reason)
		durationMs := time.Since(startTime).Milliseconds()

		decision := "deny"
		if isAudit {
			decision = "shadow_deny"
		}

		auditEntry := audit.AuditEntry{
			SessionID:   sessionID,
			UserID:      uID,
			UserEmail:   uEmail,
			SPIFFEID:    spiffeID,
			Timestamp:   startTime.UTC(),
			Source:      "mcp-agent",
			ClientPID:   os.Getpid(),
			Executable:  executable,
			Arguments:   cmdArguments,
			FullCommand: cleaned,
			Decision:    decision,
			Reason:      reason,
			DurationMs:  durationMs,
			ExitCode:    1,
		}
		if isAudit {
			auditEntry.ExitCode = 0
			auditEntry.Reason = fmt.Sprintf("[AUDIT MODE VIOLATION] %s", reason)
		}
		_ = audit.Log(&auditEntry, cfg.AuditLogPath)
		_, _, _ = audit.Transmit(auditEntry, cfg.ServerURL, cfg.AuditLogPath)

		if !isAudit {
			denialText := fmt.Sprintf("[DENIED] %s\n[SUGGESTION] %s", reason, suggestion)
			return CallToolResult{
				Content: []ContentBlock{{
					Type: "text",
					Text: denialText,
				}},
				IsError: true,
			}
		}
	}

	// Execute inside sandbox
	output, execErr := sandbox.RunSandboxedCommand(cleaned)
	durationMs := time.Since(startTime).Milliseconds()

	if isAudit && !allowed {
		output = fmt.Sprintf("[BAP AUDIT MODE] Policy violation detected: %s. Execution permitted in audit mode.\n\n%s", reason, output)
	}

	exitCode := 0
	if execErr != nil {
		exitCode = 1
	}

	auditEntry := audit.AuditEntry{
		SessionID:   sessionID,
		UserID:      uID,
		UserEmail:   uEmail,
		SPIFFEID:    spiffeID,
		Timestamp:   startTime.UTC(),
		Source:      "mcp-agent",
		ClientPID:   os.Getpid(),
		Executable:  executable,
		Arguments:   cmdArguments,
		FullCommand: cleaned,
		Decision:    "allow",
		DurationMs:  durationMs,
		ExitCode:    exitCode,
	}
	_ = audit.Log(&auditEntry, cfg.AuditLogPath)
	_, _, _ = audit.Transmit(auditEntry, cfg.ServerURL, cfg.AuditLogPath)

	if execErr != nil {
		return CallToolResult{
			Content: []ContentBlock{{
				Type: "text",
				Text: fmt.Sprintf("%s\n[ERROR] Command exited with code %d: %v", output, exitCode, execErr),
			}},
			IsError: true,
		}
	}

	return CallToolResult{
		Content: []ContentBlock{{
			Type: "text",
			Text: output,
		}},
		IsError: false,
	}
}

func explainPolicy(fullCommand string, authorizer *authz.Authorizer) CallToolResult {
	cleaned := sandbox.CleanCommandString(fullCommand)
	executable, cmdArguments := sandbox.ParseCommand(cleaned)

	allowed, reason, err := authorizer.Evaluate(executable, cleaned, cmdArguments)
	if err != nil {
		return CallToolResult{
			Content: []ContentBlock{{
				Type: "text",
				Text: fmt.Sprintf("Policy evaluation error: %v", err),
			}},
			IsError: true,
		}
	}

	if allowed {
		return CallToolResult{
			Content: []ContentBlock{{
				Type: "text",
				Text: fmt.Sprintf("ALLOWED: Command executable %q is permitted by BAP developer policy.", executable),
			}},
			IsError: false,
		}
	}

	suggestion := GenerateSuggestion(cleaned, executable, reason)
	explanation := fmt.Sprintf("DENIED: %s\nSUGGESTION: %s", reason, suggestion)
	return CallToolResult{
		Content: []ContentBlock{{
			Type: "text",
			Text: explanation,
		}},
		IsError: false,
	}
}

func getStatus(cfg ServerConfig) CallToolResult {
	var uID, uEmail, spiffeID string
	if cfg.IdentityResolver != nil {
		uID, uEmail, spiffeID = cfg.IdentityResolver()
	}
	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-mcp-%d", os.Getpid())
	}

	statusObj := map[string]interface{}{
		"agent": map[string]interface{}{
			"user_id":    uID,
			"user_email": uEmail,
			"spiffe_id":  spiffeID,
			"session_id": sessionID,
			"source":     "mcp-server",
		},
		"governance": map[string]interface{}{
			"model":                 "Dual-PEP (Client Edge + Network Perimeter)",
			"engine":                "Cedar Policy Engine (AWS Cedar)",
			"enforcement_mode":      cfg.EnforcementMode,
			"identity_injection":    "Active (CORP_OBO_TOKEN)",
			"audit_tamper_evidence": "Active (SHA-256 Hash Chained)",
		},
		"endpoints": map[string]string{
			"control_plane": cfg.ServerURL,
			"gateway_pep":   "http://localhost:9090",
			"local_ollama":  "http://localhost:11434",
		},
	}

	raw, _ := json.MarshalIndent(statusObj, "", "  ")
	return CallToolResult{
		Content: []ContentBlock{{
			Type: "text",
			Text: string(raw),
		}},
		IsError: false,
	}
}

// GenerateSuggestion produces intelligent, actionable advice when a command is denied.
func GenerateSuggestion(fullCmd, execName, reason string) string {
	lower := strings.ToLower(fullCmd)

	if strings.Contains(lower, "invoke-restmethod") || strings.Contains(lower, "invoke-webrequest") ||
		strings.Contains(lower, "curl") || strings.Contains(lower, "wget") ||
		strings.Contains(lower, "iwr ") || strings.Contains(lower, "irm ") ||
		strings.Contains(lower, "downloadstring") || strings.Contains(lower, "downloadfile") {
		return "External network egress is restricted by Zero-Trust policy. For local LLM inference, use 'http://localhost:11434' or 'http://127.0.0.1:11434'. For external banking APIs or web services, route through the BAP Gateway PEP (http://localhost:9090) with an authorized BAP Grant."
	}

	if strings.Contains(lower, ".env") {
		return "Direct access or tampering with .env credential files is strictly prohibited. Access required configuration via sandboxed environment variables (e.g., $env:VARIABLE) or the corporate Secret Store."
	}

	if strings.Contains(lower, ".ssh") || strings.Contains(lower, ".aws") || strings.Contains(lower, "id_rsa") {
		return "Direct access to private developer credentials (~/.ssh, ~/.aws) is blocked. Use the injected corporate identity token (CORP_OBO_TOKEN) or SPIFFE workload identities provided by BAP."
	}

	if strings.Contains(lower, "-encodedcommand") || strings.Contains(lower, "-enc ") || strings.Contains(lower, "-encoded ") {
		return "Base64-encoded PowerShell execution is blocked to prevent defense evasion. Provide the decoded PowerShell script or command directly."
	}

	if strings.Contains(lower, "tcpclient") || strings.Contains(lower, "system.net.sockets") || strings.Contains(lower, "udpclient") {
		return "Opening raw network sockets directly on the host is prohibited on edge agents. Egress must be governed through the BAP Gateway PEP."
	}

	if strings.Contains(lower, "set-mppreference") || strings.Contains(lower, "disablerealtimemonitoring") ||
		(strings.Contains(lower, "set-service") && strings.Contains(lower, "disabled")) || strings.Contains(lower, "stop-service") {
		return "Disabling or altering host security controls and antivirus preferences is strictly prohibited."
	}

	if strings.Contains(lower, "remove-item") || strings.Contains(lower, "rmdir") || strings.Contains(lower, "rd /s") {
		return "Mass recursive deletion targeting system paths is blocked to protect workspace integrity."
	}

	if strings.Contains(lower, "comsvcs") || strings.Contains(lower, "minidump") || strings.Contains(lower, "sekurlsa") ||
		strings.Contains(lower, "invoke-privesc") || strings.Contains(lower, "dumpcredentials") {
		return "Process memory dumping and credential harvesting techniques are blocked by zero-trust invariant."
	}

	return "Command executable is not in the approved developer whitelist. Permitted toolchains include: python, git, go, npm, maven, gradle, cargo, java, powershell, cmd, and standard inspection utilities."
}

func sendResult(w *bufio.Writer, id interface{}, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	bytes, _ := json.Marshal(resp)
	_, _ = w.Write(bytes)
	_ = w.WriteByte('\n')
	_ = w.Flush()
}

func sendError(w *bufio.Writer, id interface{}, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
	bytes, _ := json.Marshal(resp)
	_, _ = w.Write(bytes)
	_ = w.WriteByte('\n')
	_ = w.Flush()
}

func sendToolError(w *bufio.Writer, id interface{}, message string) {
	result := CallToolResult{
		Content: []ContentBlock{{
			Type: "text",
			Text: "[ERROR] " + message,
		}},
		IsError: true,
	}
	sendResult(w, id, result)
}
