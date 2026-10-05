package cmd

import (
	"bap-edge/internal/httptransport"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/authz"
	"bap-edge/internal/config"
	"bap-edge/internal/sandbox"
	"bap-edge/pkg/types"
)

type execContext struct {
	startTime       time.Time
	source          string
	sessionID       string
	serverURL       string
	policyPath      string
	auditLogPath    string
	fullCommand     string
	executable      string
	cmdArguments    string
	enforcementMode string
	decisionOnly    bool
	shadowDenied    bool
	shadowReason    string
	forceJSON       bool
	forceRaw        bool
	userPrompt      string
}

type sessionRiskState struct {
	SessionID      string    `json:"session_id"`
	DenialCount    int       `json:"denial_count"`
	LastDenial     time.Time `json:"last_denial"`
	ThreatLevel    string    `json:"threat_level"`
	AttemptHistory []string  `json:"attempt_history"`
}

func recordSessionDenial(sessionID, fullCmd, reason string) (int, string) {
	if sessionID == "" {
		sessionID = "default"
	}
	_ = os.MkdirAll(".bap", 0700)
	riskPath := filepath.Join(".bap", "risk_state.json")

	var allRisks map[string]*sessionRiskState
	data, err := os.ReadFile(riskPath)
	if err == nil {
		_ = json.Unmarshal(data, &allRisks)
	}
	if allRisks == nil {
		allRisks = make(map[string]*sessionRiskState)
	}

	rec, exists := allRisks[sessionID]
	if !exists || rec == nil {
		rec = &sessionRiskState{
			SessionID:      sessionID,
			DenialCount:    0,
			AttemptHistory: []string{},
		}
		allRisks[sessionID] = rec
	}

	rec.DenialCount++
	rec.LastDenial = time.Now().UTC()
	if len(rec.AttemptHistory) > 20 {
		rec.AttemptHistory = rec.AttemptHistory[1:]
	}
	rec.AttemptHistory = append(rec.AttemptHistory, strings.TrimSpace(fullCmd))

	if rec.DenialCount >= 4 {
		rec.ThreatLevel = "CRITICAL"
	} else if rec.DenialCount >= 2 {
		rec.ThreatLevel = "ELEVATED"
	} else {
		rec.ThreatLevel = "LOW"
	}

	if updatedData, err := json.MarshalIndent(allRisks, "", "  "); err == nil {
		_ = os.WriteFile(riskPath, updatedData, 0600)
	}

	return rec.DenialCount, rec.ThreatLevel
}

func isTamperingAttempt(cmdStr string) (bool, string) {
	lower := strings.ToLower(cmdStr)
	norm := strings.ReplaceAll(lower, "\\", "/")

	protectedAssets := []string{
		"policy.cedar",
		".claude/settings.json",
		".claude/hooks",
		".bap/",
		".bap-session.json",
		".bap-revoked",
		"bap-config.json",
		"bapedge.exe",
		"bapedge",
		"interceptor.exe",
		"cchook-interceptor.exe",
		"bapcontrolplane.exe",
		"bapcontrolplane",
		"bapgateway.exe",
		"bapgateway",
	}

	destructiveOperators := []string{
		"rm ", "rm -", "del ", "erase ", "remove-item", "unlink", "rmdir", "rd /", "rd ",
		">", ">>", "set-content", "out-file", "add-content", "truncate", "sed ",
		"ren ", "rename ", "move ", "mv ", "copy ", "cp ", "chmod ", "attrib ",
	}

	for _, asset := range protectedAssets {
		if strings.Contains(norm, asset) {
			for _, op := range destructiveOperators {
				if strings.Contains(norm, op) {
					return true, fmt.Sprintf("Security Invariant Violation: Direct modification, deletion, or tampering with BAP protected asset %q is strictly forbidden.", asset)
				}
			}
		}
	}
	return false, ""
}

func generateExecutionReceipt(ec *execContext, result string, exitCode int) *types.ExecutionReceipt {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(ec.fullCommand)))
	requestHash := fmt.Sprintf("sha256:%x", h.Sum(nil))

	policyHash := ""
	polPath := ec.policyPath
	if polPath == "" {
		polPath = "policy.cedar"
	}
	var pBytes []byte
	candidates := []string{polPath, filepath.Join("..", polPath), filepath.Join("..", "..", polPath)}
	for _, cand := range candidates {
		if data, err := os.ReadFile(cand); err == nil && len(data) > 0 {
			pBytes = data
			break
		}
	}
	if len(pBytes) == 0 {
		pBytes = []byte("permit(principal, action, resource);")
	}
	ph := sha256.Sum256(pBytes)
	policyHash = fmt.Sprintf("sha256:%x", ph[:16])

	uID, _, spiffeID := resolveLocalIdentity()
	identity := spiffeID
	if identity == "" || identity == "NA" || !strings.HasPrefix(identity, "spiffe://") {
		src := ec.source
		if src == "" {
			src = "agent"
		}
		identity = fmt.Sprintf("spiffe://bap.local/agent/%s", src)
	}

	userStr := uID
	if userStr == "" {
		userStr = os.Getenv("USERNAME")
		if userStr == "" {
			userStr = os.Getenv("USER")
		}
	}
	if userStr == "" {
		userStr = "unknown-user"
	}
	delegation := fmt.Sprintf("user:%s->agent:%s", userStr, ec.source)

	sandboxProfile := sandbox.GetActiveProfile()
	if ec.decisionOnly {
		sandboxProfile = "bap-decision-only"
	}

	ts := ec.startTime.UTC()
	receiptSeed := fmt.Sprintf("%s-%s-%d", requestHash, ec.sessionID, ts.UnixNano())
	rSum := sha256.Sum256([]byte(receiptSeed))
	receiptID := fmt.Sprintf("rcpt-%x-%d", rSum[:6], ts.Unix())

	return &types.ExecutionReceipt{
		ReceiptID:      receiptID,
		RequestHash:    requestHash,
		Identity:       identity,
		Delegation:     delegation,
		PolicyVersion:  policyHash,
		PolicyHash:     policyHash,
		SandboxProfile: sandboxProfile,
		SessionID:      ec.sessionID,
		Timestamp:      ts,
		Result:         result,
	}
}

func (ec *execContext) exit(resp types.ExecResponse, code int) {
	resp.ExitCode = code

	result := "ALLOWED_EXECUTED"
	if ec.decisionOnly {
		result = "DECISION_ONLY"
	} else if ec.shadowDenied {
		result = "AUDIT_PERMITTED"
	} else if !resp.Allowed {
		if strings.Contains(strings.ToLower(resp.Reason), "tamper") {
			result = "DENIED_TAMPER"
		} else {
			result = "DENIED_POLICY"
		}
		denialCount, threatLevel := recordSessionDenial(ec.sessionID, ec.fullCommand, resp.Reason)
		if denialCount >= 2 {
			if resp.Warning == "" {
				resp.Warning = fmt.Sprintf("[CORRELATED RISK EVENT] Repeated alternative attempts detected (%d denials in session %q, Threat Level: %s)", denialCount, ec.sessionID, threatLevel)
			}
		}
	} else if code != 0 {
		result = "EXECUTION_FAILED"
	}

	if resp.Receipt == nil {
		resp.Receipt = generateExecutionReceipt(ec, result, code)
	}

	if !resp.Allowed && resp.Suggestion == "" {
		resp.Suggestion = GenerateSuggestion(ec.fullCommand, ec.executable, resp.Reason)
	}
	durationMs := time.Since(ec.startTime).Milliseconds()
	decision := "deny"
	if resp.Allowed {
		decision = "allow"
	}
	if ec.shadowDenied {
		decision = "shadow_deny"
	}
	uID, uEmail, spiffeID := resolveLocalIdentity()
	uPrompt := ec.userPrompt
	if uPrompt == "" {
		uPrompt = os.Getenv("BAP_USER_PROMPT")
	}
	entry := audit.AuditEntry{
		SessionID:   ec.sessionID,
		UserPrompt:  uPrompt,
		UserID:      uID,
		UserEmail:   uEmail,
		SPIFFEID:    spiffeID,
		Timestamp:   ec.startTime.UTC(),
		Source:      ec.source,
		ClientPID:   os.Getpid(),
		Executable:  ec.executable,
		Arguments:   ec.cmdArguments,
		FullCommand: ec.fullCommand,
		Decision:    decision,
		Reason:      resp.Reason,
		DurationMs:  durationMs,
		ExitCode:    code,
	}
	if ec.shadowDenied && entry.Reason == "" {
		entry.Reason = fmt.Sprintf("[AUDIT MODE VIOLATION] %s", ec.shadowReason)
	} else if !resp.Allowed && entry.Reason == "" {
		entry.Reason = "Blocked by security policy"
	}
	_ = audit.Log(&entry, ec.auditLogPath)
	_, _, _ = audit.Transmit(entry, ec.serverURL, ec.auditLogPath)

	exitWithResponse(resp, code, ec.forceJSON, ec.forceRaw, isAgentEnvironment(ec.source))
}

// RunExec handles the 'exec' subcommand.
func RunExec(args []string) {
	startTime := time.Now()

	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy.cedar file (defaults to ./policy.cedar)")
	jsonFlag := fs.Bool("json", false, "Output in JSON format (default: auto-detect TTY)")
	rawFlag := fs.Bool("raw", false, "Force output in raw text format")

	defaultSource := os.Getenv("LTD_SOURCE")
	if defaultSource == "" {
		defaultSource = "cli"
	}
	sourceFlag := fs.String("source", defaultSource, "Identifier of agent invoking command (e.g. claude-code, copilot, cli)")
	auditLogFlag := fs.String("audit-log", "", "Path to audit log file in JSON lines (defaults to LTD_AUDIT_LOG or ltd-audit.jsonl, 'off' to disable)")

	defaultSession := os.Getenv("BAP_SESSION_ID")
	if defaultSession == "" {
		defaultSession = os.Getenv("LTD_SESSION_ID")
	}
	sessionFlag := fs.String("session-id", defaultSession, "Session identifier for grouping agent actions")

	epCfg := config.ResolveEndpoints()
	serverFlag := fs.String("server", epCfg.ControlPlaneURL, "Central control plane URL for telemetry streaming")
	modeFlag := fs.String("mode", epCfg.EnforcementMode, "Enforcement mode: 'enforce' (default) or 'audit'/'shadow'")
	decisionOnlyFlag := fs.Bool("decision-only", false, "Evaluate policy and log audit decision without executing the command")
	checkOnlyFlag := fs.Bool("check-only", false, "Alias for --decision-only")
	cmdB64Flag := fs.String("cmd-b64", "", "Base64-encoded command string (safe broker handoff)")
	promptFlag := fs.String("prompt", os.Getenv("BAP_USER_PROMPT"), "User prompt driving the command (e.g. 'Investigate auth issue')")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	ec := &execContext{
		startTime:       startTime,
		source:          *sourceFlag,
		sessionID:       *sessionFlag,
		serverURL:       *serverFlag,
		policyPath:      *policyPath,
		auditLogPath:    *auditLogFlag,
		enforcementMode: strings.ToLower(strings.TrimSpace(*modeFlag)),
		decisionOnly:    *decisionOnlyFlag || *checkOnlyFlag,
		forceJSON:       *jsonFlag,
		forceRaw:        *rawFlag,
		userPrompt:      *promptFlag,
	}

	cmdArgs := fs.Args()
	var fullCommand string

	if *cmdB64Flag != "" {
		decoded, err := base64.StdEncoding.DecodeString(*cmdB64Flag)
		if err != nil {
			resp := types.ExecResponse{
				Allowed: false,
				Reason:  fmt.Sprintf("Failed to decode base64 command payload (--cmd-b64): %v", err),
				Mode:    ec.enforcementMode,
			}
			ec.exit(resp, 1)
			return
		}
		fullCommand = string(decoded)
	} else {
		if len(cmdArgs) == 0 {
			resp := types.ExecResponse{
				Allowed: false,
				Reason:  "No command provided to exec. Usage: ltd-agent exec <shell_command>",
				Mode:    ec.enforcementMode,
			}
			ec.exit(resp, 1)
			return
		}

		// Join all remaining args as the shell command string, preserving quotes for arguments with spaces
		if len(cmdArgs) == 1 {
			fullCommand = strings.TrimSpace(cmdArgs[0])
		} else {
			var parts []string
			for _, arg := range cmdArgs {
				parts = append(parts, quoteArg(arg))
			}
			fullCommand = strings.Join(parts, " ")
		}
	}
	fullCommand = sandbox.CleanCommandString(fullCommand)
	ec.fullCommand = fullCommand

	// Pre-flight anti-tampering check:
	// Verify if the agent attempts to modify, rename, delete, or overwrite BAP hooks, policies, or binaries
	if isTamper, tamperReason := isTamperingAttempt(fullCommand); isTamper {
		resp := types.ExecResponse{
			Allowed: false,
			Reason:  tamperReason,
			Mode:    ec.enforcementMode,
		}
		ec.exit(resp, 1)
		return
	}

	// Fast sync of remote revocations from control plane if reachable
	syncRevocationsFast(ec.serverURL, *policyPath)

	// Check if this session or the system has been revoked by CISO administrator
	if revErr := authz.CheckSessionRevocation(*policyPath, ec.sessionID); revErr != nil {
		resp := types.ExecResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("EXECUTION BLOCKED: %v", revErr),
			Mode:    ec.enforcementMode,
		}
		ec.exit(resp, 1)
	}

	// 1. Initialize Cedar authorizer
	authorizer, err := authz.NewAuthorizer(*policyPath)
	if err != nil {
		resp := types.ExecResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("Failed to load Cedar policy: %v", err),
			Mode:    ec.enforcementMode,
		}
		ec.exit(resp, 1)
	}

	// 2. Parse command for Cedar context
	executable, cmdArguments := sandbox.ParseCommand(fullCommand)
	ec.executable = executable
	ec.cmdArguments = cmdArguments

	// 3. Evaluate command against Cedar policies
	allowed, reason, err := authorizer.Evaluate(executable, fullCommand, cmdArguments)
	if err != nil {
		resp := types.ExecResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("Error during Cedar policy evaluation: %v", err),
			Mode:    ec.enforcementMode,
		}
		ec.exit(resp, 1)
	}

	if !allowed {
		suggestion := ""
		if strings.Contains(reason, "escapes_workspace") || authz.CheckCommandWorkspaceEscape(authz.GetWorkspaceRoot(), fullCommand) {
			suggestion = "Directory traversal outside the workspace is prohibited. Commands and file paths must remain within the workspace boundary. Child project access (e.g. Maven child modules) inside the workspace is permitted."
		}
		if suggestion == "" {
			suggestion = GenerateSuggestion(fullCommand, executable, reason)
		}

		if strings.EqualFold(ec.enforcementMode, "audit") || strings.EqualFold(ec.enforcementMode, "shadow") {
			ec.shadowDenied = true
			ec.shadowReason = reason
			fmt.Fprintf(os.Stderr, "[BAP AUDIT MODE] Policy violation detected: %s. Execution permitted in audit mode.\n", reason)
		} else {
			resp := types.ExecResponse{
				Allowed:    false,
				Reason:     reason,
				Suggestion: suggestion,
				Mode:       ec.enforcementMode,
			}
			ec.exit(resp, 1)
		}
	}

	// 4. Decision-Only Mode Check:
	// If decision-only mode was requested (e.g. from Claude Code PreToolUse hook),
	// return the authorization decision immediately without executing the command.
	// This guarantees that the native agent executes the command exactly once.
	if ec.decisionOnly {
		resp := types.ExecResponse{
			Allowed:      true,
			DecisionOnly: true,
			Mode:         ec.enforcementMode,
		}
		if ec.shadowDenied {
			resp.Warning = fmt.Sprintf("[BAP AUDIT MODE] Policy violation detected: %s. Execution permitted in audit mode.", ec.shadowReason)
			resp.Reason = ec.shadowReason
			resp.Suggestion = GenerateSuggestion(fullCommand, executable, ec.shadowReason)
		}
		ec.exit(resp, 0)
		return
	}

	// 5. Execute sandboxed command (allowed by Cedar or permitted in audit mode)
	output, exitCode, execErr := sandbox.RunSandboxedCommandWithExitCode(fullCommand)

	resp := types.ExecResponse{
		Allowed:  true,
		Output:   output,
		ExitCode: exitCode,
		Mode:     ec.enforcementMode,
	}
	if ec.shadowDenied {
		resp.Warning = fmt.Sprintf("[BAP AUDIT MODE] Policy violation detected: %s. Execution permitted in audit mode.", ec.shadowReason)
		resp.Reason = ec.shadowReason
		resp.Suggestion = GenerateSuggestion(fullCommand, executable, ec.shadowReason)
	}
	if execErr != nil {
		resp.Reason = fmt.Sprintf("Command execution failed: %v", execErr)
		ec.exit(resp, exitCode)
		return
	}
	ec.exit(resp, exitCode)
}

// RunCheck executes policy evaluation in decision-only mode (bapedge check <cmd>).
func RunCheck(args []string) {
	RunExec(append([]string{"--decision-only"}, args...))
}

func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func isAgentEnvironment(source string) bool {
	if source != "" && source != "cli" {
		return true
	}
	agentEnvs := []string{
		"BAP_SESSION_ID",
		"LTD_SESSION_ID",
		"ANTIGRAVITY",
		"AGY_SESSION",
		"GEMINI_AGENT",
		"CLAUDE_CODE",
		"COPILOT_AGENT",
		"AI_AGENT",
		"AGENT_NAME",
		"AUTO_GPT",
	}
	for _, envKey := range agentEnvs {
		if os.Getenv(envKey) != "" {
			return true
		}
	}
	return false
}

func exitWithResponse(resp types.ExecResponse, code int, forceJSON, forceRaw bool, isAgent bool) {
	outputJSON := forceJSON || (!forceRaw && (!isTerminal(os.Stdout) || isAgent))

	if outputJSON {
		printJSONAndExit(resp, code)
		return
	}

	// Human-friendly / interactive terminal output
	if !resp.Allowed {
		fmt.Fprintf(os.Stderr, "[DENIED] %s\n", resp.Reason)
		if resp.Suggestion != "" {
			fmt.Fprintf(os.Stderr, "[SUGGESTION] %s\n", resp.Suggestion)
		}
		fmt.Fprintf(os.Stderr, "[TIP] Pass '-json' to receive machine-readable structured JSON responses.\n")
		os.Exit(code)
	}

	if resp.DecisionOnly {
		if resp.Warning != "" {
			fmt.Fprintf(os.Stderr, "[WARNING] %s\n", resp.Warning)
		}
		fmt.Println("[ALLOWED] Command authorized by BAP Cedar policy (decision-only mode)")
		os.Exit(0)
	}

	if resp.Warning != "" {
		fmt.Fprintf(os.Stderr, "[WARNING] %s\n", resp.Warning)
	}
	if resp.Output != "" {
		fmt.Println(resp.Output)
	}
	if resp.Reason != "" {
		fmt.Fprintf(os.Stderr, "[ERROR] %s\n", resp.Reason)
		if resp.Suggestion != "" {
			fmt.Fprintf(os.Stderr, "[SUGGESTION] %s\n", resp.Suggestion)
		}
	}
	os.Exit(code)
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

func printJSONAndExit(resp types.ExecResponse, code int) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
	os.Exit(code)
}

func quoteArg(arg string) string {
	if strings.HasPrefix(arg, "\"") && strings.HasSuffix(arg, "\"") && len(arg) >= 2 {
		return arg
	}
	if strings.ContainsAny(arg, " \t\r\n") {
		return `"` + arg + `"`
	}
	return arg
}

func syncRevocationsFast(serverURL, policyPath string) {
	if serverURL == "" || os.Getenv("BAP_OFFLINE") == "1" || os.Getenv("BAP_TEST_MODE") == "1" {
		return
	}
	client := httptransport.New(3 * time.Second)
	resp, err := client.Get(serverURL + "/api/v1/control/revocations")
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	var data struct {
		KillSwitch      bool     `json:"kill_switch"`
		RevokedSessions []string `json:"revoked_sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return
	}

	// Update policy-state.json inside .bap/ to avoid littering the workspace
	_ = os.MkdirAll(".bap", 0700)
	statePath := filepath.Join(".bap", "policy-state.json")
	if policyPath != "" && filepath.Dir(policyPath) != "." && filepath.Dir(policyPath) != "" {
		statePath = filepath.Join(filepath.Dir(policyPath), "policy-state.json")
	}
	// Clean up legacy root policy-state.json if it exists
	if _, err := os.Stat("policy-state.json"); err == nil {
		_ = os.Remove("policy-state.json")
	}

	var existing map[string]any
	if content, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(content, &existing)
	}
	if existing == nil {
		existing = make(map[string]any)
	}
	existing["kill_switch"] = data.KillSwitch
	existing["revoked_sessions"] = data.RevokedSessions
	existing["last_sync"] = time.Now().UTC()
	if updated, err := json.MarshalIndent(existing, "", "  "); err == nil {
		_ = os.WriteFile(statePath, updated, 0600)
	}
}
