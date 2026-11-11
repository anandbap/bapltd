package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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
			{
				Name: "bap_write_file",
				Description: "Writes content directly to a file under active BAP Zero-Trust boundary governance. " +
					"Bypasses shell command generation and syntax permutations. Cross-folder writes are strictly evaluated against workspace boundaries and active permissions.",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]string{
							"type":        "string",
							"description": "Target file path relative to workspace or absolute",
						},
						"content": map[string]string{
							"type":        "string",
							"description": "Full file content to write",
						},
					},
					Required: []string{"path", "content"},
				},
			},
			{
				Name: "bap_read_file",
				Description: "Reads file contents under active BAP Zero-Trust credential shielding (.env, .ssh, .aws forbidden).",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]string{
							"type":        "string",
							"description": "File path to read",
						},
					},
					Required: []string{"path"},
				},
			},
			{
				Name: "bap_edit_file",
				Description: "Performs exact string replacement in a file under active BAP Zero-Trust governance.",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]string{
							"type":        "string",
							"description": "Target file path",
						},
						"old_string": map[string]string{
							"type":        "string",
							"description": "Exact text to replace",
						},
						"new_string": map[string]string{
							"type":        "string",
							"description": "Replacement text",
						},
					},
					Required: []string{"path", "old_string", "new_string"},
				},
			},
			{
				Name: "bap_list_dir",
				Description: "Lists files and directories under active BAP Zero-Trust governance.",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"path": map[string]string{
							"type":        "string",
							"description": "Directory path to inspect (defaults to '.')",
						},
					},
				},
			},
			{
				Name: "bap_request_task_grant",
				Description: "Submits a cryptographically signed 4-Tuple Task Authorization Envelope (Who, AuthorizedBy, Intent, PermissionAsk) " +
					"to mint a least-privilege ephemeral JIT TaskGrant under Zero Standing Privileges.",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"session_id": map[string]string{"type": "string", "description": "Active agent session ID"},
						"mission":    map[string]string{"type": "string", "description": "Primary mission (e.g. CODE_INSPECTION, BUG_FIX)"},
						"goal":       map[string]string{"type": "string", "description": "Declared goal of this task"},
						"actions":    map[string]string{"type": "string", "description": "Comma-separated canonical actions requested"},
						"resources":  map[string]string{"type": "string", "description": "Comma-separated canonical resources (defaults to workspace://current)"},
						"max_uses":   map[string]string{"type": "integer", "description": "Max execution uses before burn (default 1)"},
					},
					Required: []string{"mission", "goal", "actions"},
				},
			},
			{
				Name: "bap_zsp_status",
				Description: "Inspects the agent's cryptographic SPIFFE SVID principal, human owner binding, " +
					"zero-standing-privilege posture, and active JIT TaskGrants.",
				InputSchema: InputSchema{
					Type: "object",
					Properties: map[string]interface{}{
						"session_id": map[string]string{"type": "string", "description": "Optional session ID"},
					},
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

		case "bap_write_file":
			res := handleWriteFile(params.Arguments, cfg)
			sendResult(w, req.ID, res)

		case "bap_read_file":
			res := handleReadFile(params.Arguments)
			sendResult(w, req.ID, res)

		case "bap_edit_file":
			res := handleEditFile(params.Arguments, cfg)
			sendResult(w, req.ID, res)

		case "bap_list_dir":
			res := handleListDir(params.Arguments)
			sendResult(w, req.ID, res)

		case "bap_request_task_grant":
			res := handleRequestTaskGrant(params.Arguments)
			sendResult(w, req.ID, res)

		case "bap_zsp_status":
			res := handleZSPStatus(params.Arguments)
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
			ReportingLayer: "mcp",
			SessionID:      sessionID,
			UserID:         uID,
			UserEmail:      uEmail,
			SPIFFEID:       spiffeID,
			Timestamp:      startTime.UTC(),
			Source:         "mcp-agent",
			ClientPID:      os.Getpid(),
			Executable:     executable,
			Arguments:      cmdArguments,
			FullCommand:    cleaned,
			Decision:       decision,
			Reason:         reason,
			DurationMs:     durationMs,
			ExitCode:       1,
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
		ReportingLayer: "mcp",
		SessionID:      sessionID,
		UserID:         uID,
		UserEmail:      uEmail,
		SPIFFEID:       spiffeID,
		Timestamp:      startTime.UTC(),
		Source:         "mcp-agent",
		ClientPID:      os.Getpid(),
		Executable:     executable,
		Arguments:      cmdArguments,
		FullCommand:    cleaned,
		Decision:       "allow",
		DurationMs:     durationMs,
		ExitCode:       exitCode,
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
			"model":                 "5-Layer Defense-in-Depth (Hooks -> MCP -> Shims -> Kernel Sandbox -> Perimeter Gateway PEP)",
			"engine":                "Cedar Policy Engine (AWS Cedar)",
			"enforcement_mode":      cfg.EnforcementMode,
			"identity_injection":    "Active (CORP_OBO_TOKEN)",
			"audit_tamper_evidence": "Active (SHA-256 Hash Chained)",
		},
		"defense_layers": map[string]interface{}{
			"architecture": "5-Layer Defense-in-Depth",
			"layers": []map[string]interface{}{
				{"layer": "Layer 1", "name": "Process Interception Hooks", "status": "NOT_OBSERVED", "description": "Native hook approval and execution must be verified independently"},
				{"layer": "Layer 2", "name": "Model Context Protocol (MCP)", "status": "AVAILABLE", "description": "This MCP server evaluates and reports calls routed through its tools"},
				{"layer": "Layer 3", "name": "Terminal Interceptor Shims", "status": "NOT_OBSERVED", "description": "Requires commands to resolve through the installed PATH shims"},
				{"layer": "Layer 4", "name": "OS Kernel Boundary & Broker", "status": "NOT_OBSERVED", "description": "Broker execution and OS-wide containment require separate runtime evidence"},
				{"layer": "Layer 5", "name": "Authoritative Network Gateway PEP", "status": "NOT_OBSERVED", "description": "Gateway reports protected resource operations using its own service identity"},
			},
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

func resolveMCPSessionID(args map[string]interface{}) string {
	if s, ok := args["session_id"].(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	if s := strings.TrimSpace(os.Getenv("BAP_SESSION_ID")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("LTD_SESSION_ID")); s != "" {
		return s
	}
	return fmt.Sprintf("sess-mcp-%d", os.Getpid())
}

func handleRequestTaskGrant(args map[string]interface{}) CallToolResult {
	sessionID := resolveMCPSessionID(args)
	mission, _ := args["mission"].(string)
	goal, _ := args["goal"].(string)
	actionsStr, _ := args["actions"].(string)
	resourcesStr, _ := args["resources"].(string)
	maxUses := 1
	hasMaxUses := false
	if mu, ok := args["max_uses"].(float64); ok && mu > 0 {
		maxUses = int(mu)
		hasMaxUses = true
	}
	var actions, resources []string
	for _, a := range strings.Split(actionsStr, ",") {
		if t := strings.TrimSpace(a); t != "" {
			actions = append(actions, t)
		}
	}
	if !hasMaxUses && len(actions) > 1 {
		maxUses = len(actions)
	}
	for _, r := range strings.Split(resourcesStr, ",") {
		if t := strings.TrimSpace(r); t != "" {
			resources = append(resources, t)
		}
	}
	grant, env, err := authz.SubmitTaskEnvelope(
		authz.ResolveZSPDir(), sessionID, "mcp-agent", mission, goal, goal,
		actions, resources, "", maxUses, 300*time.Second,
	)
	if err != nil {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("TaskEnvelope denied: %v", err)}},
			IsError: true,
		}
	}
	raw, _ := json.MarshalIndent(map[string]any{
		"allowed":     true,
		"envelope_id": env.EnvelopeID,
		"grant":       grant,
	}, "", "  ")
	return CallToolResult{
		Content: []ContentBlock{{Type: "text", Text: string(raw)}},
		IsError: false,
	}
}

func handleZSPStatus(args map[string]interface{}) CallToolResult {
	sessionID := resolveMCPSessionID(args)
	rep, err := authz.ListSessionZSPStatus(authz.ResolveZSPDir(), sessionID, "mcp-agent")
	if err != nil {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("ZSP status error: %v", err)}},
			IsError: true,
		}
	}
	raw, _ := json.MarshalIndent(rep, "", "  ")
	return CallToolResult{
		Content: []ContentBlock{{Type: "text", Text: string(raw)}},
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

	return "Command executable is not in the approved developer whitelist. Permitted toolchains include: python, git, go, npm, maven, gradle, cargo, java, powershell, cmd, and standard inspection utilities (sed, awk, grep, diff, etc.)."
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

func handleWriteFile(args map[string]interface{}, cfg ServerConfig) CallToolResult {
	pathVal, _ := args["path"].(string)
	contentVal, _ := args["content"].(string)
	if strings.TrimSpace(pathVal) == "" {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: "Parameter 'path' is required"}},
			IsError: true,
		}
	}
	workspaceRoot := authz.GetWorkspaceRoot()
	var absPath string
	if filepath.IsAbs(pathVal) {
		absPath = filepath.Clean(pathVal)
	} else {
		absPath = filepath.Clean(filepath.Join(workspaceRoot, pathVal))
	}

	// 1. Check secret paths (.env, .ssh, ~/.aws)
	if isSecret, reason := authz.IsForbiddenSecretPath(absPath); isSecret {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("[BAP ZERO-TRUST] Security Invariant Violation: Access to sensitive credential stores is strictly forbidden: %s", reason)}},
			IsError: true,
		}
	}

	// 2. Check workspace escape
	if workspaceRoot != "" && authz.IsPathOutsideWorkspaceCanonical(workspaceRoot, absPath) {
		if auth, _ := authz.IsTargetAuthorized(workspaceRoot, cfg.SessionID, absPath, "write"); !auth {
			return CallToolResult{
				Content: []ContentBlock{{
					Type: "text",
					Text: fmt.Sprintf("[BAP ZERO-TRUST] Execution blocked: Directory traversal outside workspace is forbidden for path: %s\nCommands modifying files outside workspace require authorization. To authorize this path, run: ! bapedge trust %q --project (or --session).", pathVal, pathVal),
				}},
				IsError: true,
			}
		}
	}

	// 3. Write file
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Failed to create parent directory: %v", err)}},
			IsError: true,
		}
	}
	if err := os.WriteFile(absPath, []byte(contentVal), 0644); err != nil {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Failed to write file: %v", err)}},
			IsError: true,
		}
	}

	// 4. Emit Audit Telemetry
	startTime := time.Now()
	uID, uEmail, spiffeID := "developer", "developer@enterprise.local", "spiffe://enterprise.local/agent/mcp"
	if cfg.IdentityResolver != nil {
		uID, uEmail, spiffeID = cfg.IdentityResolver()
	}
	auditEntry := audit.AuditEntry{
		ReportingLayer: "mcp",
		SessionID:      cfg.SessionID,
		UserID:         uID,
		UserEmail:      uEmail,
		SPIFFEID:       spiffeID,
		Timestamp:      startTime.UTC(),
		Source:         "mcp-file-tool",
		ClientPID:      os.Getpid(),
		Executable:     "bap_write_file",
		Arguments:      pathVal,
		FullCommand:    fmt.Sprintf("bap_write_file %s (%d bytes)", pathVal, len(contentVal)),
		Decision:       "allow",
		DurationMs:     1,
		ExitCode:       0,
	}
	_ = audit.Log(&auditEntry, cfg.AuditLogPath)
	_, _, _ = audit.Transmit(auditEntry, cfg.ServerURL, cfg.AuditLogPath)

	return CallToolResult{
		Content: []ContentBlock{{
			Type: "text",
			Text: fmt.Sprintf("Successfully wrote %d bytes to %s", len(contentVal), absPath),
		}},
		IsError: false,
	}
}

func handleReadFile(args map[string]interface{}) CallToolResult {
	pathVal, _ := args["path"].(string)
	if strings.TrimSpace(pathVal) == "" {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: "Parameter 'path' is required"}},
			IsError: true,
		}
	}
	workspaceRoot := authz.GetWorkspaceRoot()
	var absPath string
	if filepath.IsAbs(pathVal) {
		absPath = filepath.Clean(pathVal)
	} else {
		absPath = filepath.Clean(filepath.Join(workspaceRoot, pathVal))
	}
	if isSecret, reason := authz.IsForbiddenSecretPath(absPath); isSecret {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("[BAP ZERO-TRUST] Security Invariant Violation: Access to sensitive credential stores is strictly forbidden: %s", reason)}},
			IsError: true,
		}
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Failed to read file: %v", err)}},
			IsError: true,
		}
	}
	return CallToolResult{
		Content: []ContentBlock{{
			Type: "text",
			Text: string(data),
		}},
		IsError: false,
	}
}

func handleEditFile(args map[string]interface{}, cfg ServerConfig) CallToolResult {
	pathVal, _ := args["path"].(string)
	oldStr, _ := args["old_string"].(string)
	newStr, _ := args["new_string"].(string)
	if strings.TrimSpace(pathVal) == "" || oldStr == "" {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: "Parameters 'path' and 'old_string' are required"}},
			IsError: true,
		}
	}
	workspaceRoot := authz.GetWorkspaceRoot()
	var absPath string
	if filepath.IsAbs(pathVal) {
		absPath = filepath.Clean(pathVal)
	} else {
		absPath = filepath.Clean(filepath.Join(workspaceRoot, pathVal))
	}
	if isSecret, reason := authz.IsForbiddenSecretPath(absPath); isSecret {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("[BAP ZERO-TRUST] Security Invariant Violation: Access to sensitive credential stores is strictly forbidden: %s", reason)}},
			IsError: true,
		}
	}
	if workspaceRoot != "" && authz.IsPathOutsideWorkspaceCanonical(workspaceRoot, absPath) {
		if auth, _ := authz.IsTargetAuthorized(workspaceRoot, cfg.SessionID, absPath, "write"); !auth {
			return CallToolResult{
				Content: []ContentBlock{{
					Type: "text",
					Text: fmt.Sprintf("[BAP ZERO-TRUST] Execution blocked: Directory traversal outside workspace is forbidden for path: %s\nCommands modifying files outside workspace require authorization. To authorize this path, run: ! bapedge trust %q --project (or --session).", pathVal, pathVal),
				}},
				IsError: true,
			}
		}
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Failed to read file for editing: %v", err)}},
			IsError: true,
		}
	}
	content := string(data)
	if !strings.Contains(content, oldStr) {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: "old_string not found in target file"}},
			IsError: true,
		}
	}
	updated := strings.Replace(content, oldStr, newStr, 1)
	if err := os.WriteFile(absPath, []byte(updated), 0644); err != nil {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Failed to save edited file: %v", err)}},
			IsError: true,
		}
	}
	return CallToolResult{
		Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Successfully edited %s", absPath)}},
		IsError: false,
	}
}

func handleListDir(args map[string]interface{}) CallToolResult {
	pathVal, _ := args["path"].(string)
	if pathVal == "" {
		pathVal = "."
	}
	workspaceRoot := authz.GetWorkspaceRoot()
	var absPath string
	if filepath.IsAbs(pathVal) {
		absPath = filepath.Clean(pathVal)
	} else {
		absPath = filepath.Clean(filepath.Join(workspaceRoot, pathVal))
	}
	entries, err := os.ReadDir(absPath)
	if err != nil {
		return CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Failed to list directory: %v", err)}},
			IsError: true,
		}
	}
	var lines []string
	for _, e := range entries {
		info, _ := e.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		typeStr := "file"
		if e.IsDir() {
			typeStr = "dir"
		}
		lines = append(lines, fmt.Sprintf("%-6s %10d %s", typeStr, size, e.Name()))
	}
	return CallToolResult{
		Content: []ContentBlock{{Type: "text", Text: strings.Join(lines, "\n")}},
		IsError: false,
	}
}
