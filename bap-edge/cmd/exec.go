package cmd

import (
	"bytes"
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

	"bap-edge/internal/antibypass"
	"bap-edge/internal/audit"
	"bap-edge/internal/authz"
	"bap-edge/internal/config"
	"bap-edge/internal/fim"
	"bap-edge/internal/pinning"
	"bap-edge/internal/sandbox"
	"bap-edge/internal/snapshot"
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
	skillName       string
	contentHash     string
	stepUpDecision  string
	parentPID       int
	processPID      int
	processTree     []string
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

type sessionApprovalRecord struct {
	SessionID           string            `json:"session_id"`
	ApprovedCommands    map[string]string `json:"approved_commands"`
	ApprovedExecutables map[string]bool   `json:"approved_executables"`
}

func getSessionApprovalsPath(sessionID string) string {
	_ = os.MkdirAll(".bap", 0700)
	safeID := strings.ReplaceAll(sessionID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	safeID = strings.ReplaceAll(safeID, "\\", "_")
	return filepath.Join(".bap", fmt.Sprintf("approvals_%s.json", safeID))
}

func isSessionTrustGranted(sessionID, fullCommand, executable string) bool {
	if sessionID == "" {
		return false
	}
	path := getSessionApprovalsPath(sessionID)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var rec sessionApprovalRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return false
	}
	normExec := strings.ToLower(strings.TrimSpace(executable))
	if rec.ApprovedExecutables != nil && rec.ApprovedExecutables[normExec] {
		return true
	}
	cmdHash := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(fullCommand))))
	if rec.ApprovedCommands != nil && rec.ApprovedCommands[cmdHash] == "session" {
		return true
	}
	return false
}

func recordSessionTrust(sessionID, fullCommand, executable, approvalType string) {
	if sessionID == "" {
		sessionID = "default"
	}
	path := getSessionApprovalsPath(sessionID)
	var rec sessionApprovalRecord
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &rec)
	}
	rec.SessionID = sessionID
	if rec.ApprovedCommands == nil {
		rec.ApprovedCommands = make(map[string]string)
	}
	if rec.ApprovedExecutables == nil {
		rec.ApprovedExecutables = make(map[string]bool)
	}
	cmdHash := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(fullCommand))))
	rec.ApprovedCommands[cmdHash] = approvalType
	if approvalType == "session" {
		normExec := strings.ToLower(strings.TrimSpace(executable))
		if normExec != "" {
			rec.ApprovedExecutables[normExec] = true
		}
	}
	if b, err := json.MarshalIndent(rec, "", "  "); err == nil {
		_ = os.WriteFile(path, b, 0600)
	}
}

func promptHumanStepUpApproval(ec *execContext, fullCommand, executable, reason string) string {
	// 1. Check if session already trusts this command or executable
	if isSessionTrustGranted(ec.sessionID, fullCommand, executable) {
		return "session_trust"
	}

	// 2. Anti-tampering check: BAP protected assets are NEVER eligible for step-up escalation
	if isTamper, _ := isTamperingAttempt(fullCommand); isTamper {
		return "denied"
	}

	// Determine if this is a cross-folder mutation
	decomp := authz.Decompose(executable, fullCommand, ec.cmdArguments)
	targetEntity := decomp.TargetEntity
	if targetEntity == "" || targetEntity == executable {
		if parts := strings.Split(fullCommand, ">"); len(parts) > 1 {
			targetEntity = strings.TrimSpace(strings.Trim(parts[len(parts)-1], "\"'`"))
		}
	}
	workspaceRoot := authz.GetWorkspaceRoot()
	var absTarget string
	if targetEntity != "" {
		if filepath.IsAbs(targetEntity) {
			absTarget = filepath.Clean(targetEntity)
		} else if workspaceRoot != "" {
			absTarget = filepath.Clean(filepath.Join(workspaceRoot, targetEntity))
		}
	}

	escapes := authz.CheckCommandWorkspaceEscape(workspaceRoot, fullCommand)
	if absTarget != "" && workspaceRoot != "" && authz.IsPathOutsideWorkspaceCanonical(workspaceRoot, absTarget) {
		escapes = true
	}

	isCrossFolder := escapes && (decomp.ActionType == "write" || decomp.ActionType == "delete" || strings.Contains(strings.ToLower(reason), "policy2") || strings.Contains(strings.ToLower(reason), "escapes_workspace") || strings.Contains(strings.ToLower(reason), "escapes workspace"))

	// Check if target is already authorized via session/project/global
	if isCrossFolder && absTarget != "" {
		if auth, scope := authz.IsTargetAuthorized(workspaceRoot, ec.sessionID, absTarget, decomp.ActionType); auth {
			switch scope {
			case "project":
				return "project_trust"
			case "global":
				return "global_trust"
			default:
				return "session_trust"
			}
		}
	}

	trustPath := absTarget
	if trustPath == "" {
		trustPath = fullCommand
	}

	// 3. Automated / Environment Override for CI/CD, headless pipelines, or test harnesses
	envDecision := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_STEPUP_DECISION")))
	if envDecision == "approve" || envDecision == "once" || envDecision == "allow" || envDecision == "o" {
		return "approve_once"
	}
	if envDecision == "project" || envDecision == "p" {
		if isCrossFolder && absTarget != "" {
			_ = authz.GrantPermission(workspaceRoot, ec.sessionID, absTarget, "project", []string{decomp.ActionType})
		}
		return "project_trust"
	}
	if envDecision == "global" || envDecision == "g" {
		if isCrossFolder && absTarget != "" {
			_ = authz.GrantPermission(workspaceRoot, ec.sessionID, absTarget, "global", []string{decomp.ActionType})
		}
		return "global_trust"
	}
	if envDecision == "session" || envDecision == "trust" || envDecision == "s" {
		if isCrossFolder && absTarget != "" {
			_ = authz.GrantPermission(workspaceRoot, ec.sessionID, absTarget, "session", []string{decomp.ActionType})
		}
		recordSessionTrust(ec.sessionID, fullCommand, executable, "session")
		return "session_trust"
	}
	if envDecision == "deny" || envDecision == "block" || envDecision == "d" {
		return "denied"
	}

	// 4. Interactive Terminal Check:
	// If non-interactive (piped stdin, CI, or explicit flag), fail-closed
	if !isTerminal(os.Stdin) || os.Getenv("BAP_NON_INTERACTIVE") == "1" || ec.forceJSON {
		return "non_interactive_deny"
	}

	// 5. Interactive Human-in-the-Loop Prompt on terminal
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "================================================================================\n")
	if isCrossFolder {
		fmt.Fprintf(os.Stderr, " [BAP AIR SECURITY KERNEL] CROSS-FOLDER MUTATION APPROVAL REQUIRED (HITL)\n")
		fmt.Fprintf(os.Stderr, "================================================================================\n")
		fmt.Fprintf(os.Stderr, " Session ID   : %s\n", ec.sessionID)
		fmt.Fprintf(os.Stderr, " Agent Source : %s\n", ec.source)
		fmt.Fprintf(os.Stderr, " Target Entity: %s\n", trustPath)
		fmt.Fprintf(os.Stderr, " Action Type  : %s\n", decomp.ActionType)
		fmt.Fprintf(os.Stderr, " Executable   : %s\n", executable)
		fmt.Fprintf(os.Stderr, " Command      : %s\n", fullCommand)
		fmt.Fprintf(os.Stderr, " Policy Reason: %s\n", reason)
		fmt.Fprintf(os.Stderr, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, " This operation requests cross-folder mutation outside the active workspace.\n")
		fmt.Fprintf(os.Stderr, " [O] Once     - Authorize this specific execution once\n")
		fmt.Fprintf(os.Stderr, " [S] Session  - Trust target path for remainder of this session (%s)\n", ec.sessionID)
		fmt.Fprintf(os.Stderr, " [P] Project  - Persistently trust target path across sessions for this workspace\n")
		fmt.Fprintf(os.Stderr, " [G] Global   - Persistently trust target path machine-wide across all workspaces\n")
		fmt.Fprintf(os.Stderr, " [D] Deny (Default) - Strictly block execution and maintain containment\n")
		fmt.Fprintf(os.Stderr, "================================================================================\n")
		fmt.Fprintf(os.Stderr, "[BAP HITL] Enter choice [o/s/p/g/D]: ")

		var input string
		_, _ = fmt.Fscanln(os.Stdin, &input)
		choice := strings.ToLower(strings.TrimSpace(input))

		switch choice {
		case "o", "once", "approve", "yes", "y", "a":
			return "approve_once"
		case "s", "session":
			if absTarget != "" {
				_ = authz.GrantPermission(workspaceRoot, ec.sessionID, absTarget, "session", []string{decomp.ActionType})
			}
			recordSessionTrust(ec.sessionID, fullCommand, executable, "session")
			return "session_trust"
		case "p", "project":
			if absTarget != "" {
				_ = authz.GrantPermission(workspaceRoot, ec.sessionID, absTarget, "project", []string{decomp.ActionType})
			}
			return "project_trust"
		case "g", "global":
			if absTarget != "" {
				_ = authz.GrantPermission(workspaceRoot, ec.sessionID, absTarget, "global", []string{decomp.ActionType})
			}
			return "global_trust"
		default:
			return "denied"
		}
	} else {
		fmt.Fprintf(os.Stderr, " [BAP AIR SECURITY KERNEL] HUMAN STEP-UP APPROVAL REQUIRED (HITL)\n")
		fmt.Fprintf(os.Stderr, "================================================================================\n")
		fmt.Fprintf(os.Stderr, " Session ID   : %s\n", ec.sessionID)
		fmt.Fprintf(os.Stderr, " Agent Source : %s\n", ec.source)
		fmt.Fprintf(os.Stderr, " Executable   : %s\n", executable)
		fmt.Fprintf(os.Stderr, " Command      : %s\n", fullCommand)
		fmt.Fprintf(os.Stderr, " Policy Reason: %s\n", reason)
		fmt.Fprintf(os.Stderr, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, " This operation requires human operator authorization.\n")
		fmt.Fprintf(os.Stderr, " [A] Approve Once       - Authorize this specific execution once\n")
		fmt.Fprintf(os.Stderr, " [S] Trust for Session  - Authorize executable for remainder of this session\n")
		fmt.Fprintf(os.Stderr, " [D] Deny (Default)     - Strictly block execution and record violation\n")
		fmt.Fprintf(os.Stderr, "================================================================================\n")
		fmt.Fprintf(os.Stderr, "[BAP HITL] Enter choice [a/s/D]: ")

		var input string
		_, _ = fmt.Fscanln(os.Stdin, &input)
		choice := strings.ToLower(strings.TrimSpace(input))

		switch choice {
		case "a", "approve", "yes", "y", "o", "once":
			return "approve_once"
		case "s", "session", "trust":
			recordSessionTrust(ec.sessionID, fullCommand, executable, "session")
			return "session_trust"
		default:
			return "denied"
		}
	}
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

	lineageRaw := os.Getenv("BAP_DELEGATION_LINEAGE")
	var lineage []string
	if lineageRaw != "" {
		for _, part := range strings.Split(lineageRaw, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				lineage = append(lineage, p)
			}
		}
	}
	lineageTree := os.Getenv("BAP_LINEAGE_TREE")
	if lineageTree == "" && len(lineage) > 0 {
		lineageTree = strings.Join(lineage, " -> ")
	}
	rootAgentID := os.Getenv("BAP_ROOT_AGENT_ID")
	parentGrantID := os.Getenv("BAP_PARENT_GRANT_ID")
	grantID := os.Getenv("BAP_GRANT_ID")

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
		Lineage:        lineage,
		LineageTree:    lineageTree,
		RootAgentID:    rootAgentID,
		ParentGrantID:  parentGrantID,
		GrantID:        grantID,
		ProcessTree:    ec.processTree,
		ParentPID:      ec.parentPID,
		ProcessPID:     ec.processPID,
	}
}

func (ec *execContext) exit(resp types.ExecResponse, code int) {
	resp.ExitCode = code

	result := "ALLOWED_EXECUTED"
	if ec.stepUpDecision != "" && resp.Allowed {
		result = "ALLOWED_STEPUP"
	} else if ec.decisionOnly {
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

	if ec.stepUpDecision != "" {
		resp.StepUpDecision = ec.stepUpDecision
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
		if ec.stepUpDecision != "" {
			decision = "stepup_allow"
		} else {
			decision = "allow"
		}
	}
	if ec.shadowDenied {
		decision = "shadow_deny"
	}
	uID, uEmail, spiffeID := resolveLocalIdentity()
	uPrompt := ec.userPrompt
	if uPrompt == "" {
		uPrompt = os.Getenv("BAP_USER_PROMPT")
	}
	decomp := authz.Decompose(ec.executable, ec.fullCommand, ec.cmdArguments)
	if resp.CanonicalAction == "" {
		resp.CanonicalAction = decomp.CanonicalAction
	}
	if resp.CanonicalResource == "" {
		resp.CanonicalResource = decomp.CanonicalResource
	}

	entry := audit.AuditEntry{
		SessionID:         ec.sessionID,
		UserPrompt:        uPrompt,
		UserID:            uID,
		UserEmail:         uEmail,
		SPIFFEID:          spiffeID,
		Timestamp:         ec.startTime.UTC(),
		Source:            ec.source,
		ClientPID:         os.Getpid(),
		Executable:        ec.executable,
		Arguments:         ec.cmdArguments,
		FullCommand:       ec.fullCommand,
		CanonicalAction:   decomp.CanonicalAction,
		CanonicalResource: decomp.CanonicalResource,
		ContentHash:       ec.contentHash,
		Decision:          decision,
		Reason:            resp.Reason,
		DurationMs:        durationMs,
		ExitCode:          code,
		Lineage:           resp.Receipt.Lineage,
		LineageTree:       resp.Receipt.LineageTree,
		RootAgentID:       resp.Receipt.RootAgentID,
		ParentGrantID:     resp.Receipt.ParentGrantID,
		GrantID:           resp.Receipt.GrantID,
		ProcessTree:       resp.Receipt.ProcessTree,
		ParentPID:         resp.Receipt.ParentPID,
		ProcessPID:        resp.Receipt.ProcessPID,
	}
	if ec.shadowDenied && entry.Reason == "" {
		entry.Reason = fmt.Sprintf("[AUDIT MODE VIOLATION] %s", ec.shadowReason)
	} else if !resp.Allowed && entry.Reason == "" {
		entry.Reason = "Blocked by security policy"
	}
	_ = audit.Log(&entry, ec.auditLogPath)

	daemonNotified := false
	if ds, err := ReadDaemonState(); err == nil && ds != nil {
		client := httptransport.New(200 * time.Millisecond)
		body, _ := json.Marshal(entry)
		if r, err := client.Post(ds.URL+"/api/v1/daemon/event", "application/json", bytes.NewReader(body)); err == nil {
			daemonNotified = true
			_ = r.Body.Close()
		}
	}
	if !daemonNotified {
		_, _, _ = audit.Transmit(entry, ec.serverURL, ec.auditLogPath)
	}

	exitWithResponse(resp, code, ec.forceJSON, ec.forceRaw, isAgentEnvironment(ec.source))
}

// RunExec handles the 'exec' subcommand.
func RunExec(args []string) {
	startTime := time.Now().UTC()

	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy.cedar file (defaults to ./policy.cedar)")
	jsonFlag := fs.Bool("json", false, "Output in JSON format (default: auto-detect TTY)")
	rawFlag := fs.Bool("raw", false, "Force output in raw text format")

	defaultSource := os.Getenv("LTD_SOURCE")
	if defaultSource == "" {
		defaultSource = "cli"
	}
	sourceFlag := fs.String("source", defaultSource, "Identifier of agent invoking command (e.g. claude-code, copilot, cli)")
	auditLogFlag := fs.String("audit-log", "", "Path to audit log file in JSON lines (defaults to .bapstate/audit.jsonl or LTD_AUDIT_LOG, 'off' to disable)")

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
	skillFlag := fs.String("skill", os.Getenv("BAP_SKILL_NAME"), "Identifier of declaring skill for AIR content pinning (e.g. 'sql-analyzer')")
	verifyPinsFlag := fs.Bool("verify-pins", true, "Verify cryptographic content hashes against pinning manifest (AIR Model)")
	stepUpFlag := fs.String("stepup-decision", "", "Human Step-Up approval decision ('approve', 'session', or 'deny')")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	if *stepUpFlag != "" {
		os.Setenv("BAP_STEPUP_DECISION", *stepUpFlag)
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
		skillName:       *skillFlag,
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

	// Pre-flight Anti-Bypass Enforcement Engine (BAP-560):
	// Detects unmediated subshell invocations, raw sockets, or proxy/session tampering
	antiBypass := antibypass.NewAntiBypassEngine()
	if viol, err := antiBypass.CheckCommand(ec.sessionID, fullCommand, nil); err != nil {
		resp := types.ExecResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("[DENIED_BYPASS] %s: %s", viol.Vector, viol.Reason),
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

	// Pre-flight AIR Content Pinning check (BAP-531):
	// Re-verify that declaring skill, prompt, or referenced scripts haven't drifted from pinned hashes
	if *verifyPinsFlag {
		matchedHash, pinErr := checkContentPinning(ec, *skillFlag)
		if pinErr != nil {
			resp := types.ExecResponse{
				Allowed: false,
				Reason:  fmt.Sprintf("HashMismatchError: %v", pinErr),
				Mode:    ec.enforcementMode,
			}
			ec.contentHash = matchedHash
			ec.exit(resp, 1)
			return
		}
		ec.contentHash = matchedHash
	}

	workspaceRoot, _ := os.Getwd()

	// Pre-flight File-Integrity Monitoring (FIM) & Anti-Tamper Check (BAP-537)
	fimReport, fimErr := fim.VerifyIntegrity(workspaceRoot)
	if fimErr != nil {
		resp := types.ExecResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("TamperDetected: %v", fimErr),
			Mode:    ec.enforcementMode,
		}
		ec.exit(resp, 1)
		return
	}

	// Tiered Fail-Closed Enforcement for Quarantined Endpoints (BAP-537)
	if fimReport != nil && fimReport.IsQuarantined {
		actions, _ := authz.DecomposePipeline(fullCommand, workspaceRoot)
		isEgress := false
		cmdLower := strings.ToLower(fullCommand)
		if strings.Contains(cmdLower, "curl") || strings.Contains(cmdLower, "wget") ||
			strings.Contains(cmdLower, "ssh") || strings.Contains(cmdLower, "nc ") ||
			strings.Contains(cmdLower, "aws ") || strings.Contains(cmdLower, "gh ") ||
			strings.Contains(cmdLower, "http://") || strings.Contains(cmdLower, "https://") {
			isEgress = true
		}
		for _, act := range actions {
			if act.ActionType == "network" || act.ActionType == "credential" || strings.HasPrefix(act.CanonicalResource, "http") {
				isEgress = true
				break
			}
		}
		if isEgress {
			resp := types.ExecResponse{
				Allowed: false,
				Reason:  fmt.Sprintf("QuarantinedEndpointBlocked: %s (external network egress blocked; only local offline operations permitted)", fimReport.QuarantineReason),
				Mode:    ec.enforcementMode,
			}
			ec.exit(resp, 1)
			return
		}
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
	authorizer.SetSessionID(ec.sessionID)

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

	stepUpResult := ""
	if !allowed {
		stepUpResult = promptHumanStepUpApproval(ec, fullCommand, executable, reason)
		if stepUpResult == "approve_once" || stepUpResult == "session_trust" || stepUpResult == "project_trust" || stepUpResult == "global_trust" {
			allowed = true
			ec.stepUpDecision = stepUpResult
		}
	}

	if !allowed {
		suggestion := ""
		decomp := authz.Decompose(executable, fullCommand, cmdArguments)
		targetPath := decomp.TargetEntity
		if targetPath == "" || targetPath == executable {
			if parts := strings.Split(fullCommand, ">"); len(parts) > 1 {
				targetPath = strings.TrimSpace(strings.Trim(parts[len(parts)-1], "\"'`"))
			}
		}
		if targetPath != "" && !filepath.IsAbs(targetPath) {
			targetPath = filepath.Clean(filepath.Join(authz.GetWorkspaceRoot(), targetPath))
		}

		isCrossFolder := authz.CheckCommandWorkspaceEscape(authz.GetWorkspaceRoot(), fullCommand) || (targetPath != "" && authz.IsPathOutsideWorkspaceCanonical(authz.GetWorkspaceRoot(), targetPath))

		if stepUpResult == "non_interactive_deny" {
			if isCrossFolder && targetPath != "" {
				suggestion = fmt.Sprintf("Cross-folder %s to %q outside workspace boundary requires user authorization. Authorize via 'bapedge trust %q --project' (or --session / --global), or set BAP_STEPUP_DECISION=project.", decomp.ActionType, targetPath, targetPath)
			} else {
				suggestion = "Action requires Human Step-Up Approval (HITL). In non-interactive environments, authorize via BAP_STEPUP_DECISION=approve or request a BAP Gateway Grant."
			}
		} else if isCrossFolder && targetPath != "" {
			suggestion = fmt.Sprintf("Cross-folder %s to %q outside workspace boundary was denied. To permit dependency operations outside the workspace, authorize via 'bapedge trust %q --project' (or --session / --global).", decomp.ActionType, targetPath, targetPath)
		} else if strings.Contains(reason, "escapes_workspace") || authz.CheckCommandWorkspaceEscape(authz.GetWorkspaceRoot(), fullCommand) {
			suggestion = "Directory traversal outside the workspace is prohibited. Commands and file paths must remain within the workspace boundary. Child project access (e.g. Maven child modules) inside the workspace is permitted, or grant Step-Up approval via BAP HITL."
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
				Allowed:        false,
				Reason:         reason,
				Suggestion:     suggestion,
				Mode:           ec.enforcementMode,
				StepUpDecision: "denied",
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
			Allowed:        true,
			DecisionOnly:   true,
			Mode:           ec.enforcementMode,
			StepUpDecision: ec.stepUpDecision,
		}
		if ec.stepUpDecision != "" {
			switch ec.stepUpDecision {
			case "approve_once":
				resp.Warning = fmt.Sprintf("[STEP-UP AUTHORIZED] Human operator authorized one-time execution for %q.", fullCommand)
			case "session_trust":
				resp.Warning = fmt.Sprintf("[STEP-UP AUTHORIZED: SESSION TRUST] Human operator granted session trust for %q in session %s.", executable, ec.sessionID)
			case "project_trust":
				resp.Warning = fmt.Sprintf("[STEP-UP AUTHORIZED: PROJECT TRUST] Human operator granted persistent project trust for workspace %s.", authz.GetWorkspaceRoot())
			case "global_trust":
				resp.Warning = fmt.Sprintf("[STEP-UP AUTHORIZED: GLOBAL TRUST] Human operator granted persistent global trust.")
			}
		}
		if ec.shadowDenied {
			resp.Warning = fmt.Sprintf("[BAP AUDIT MODE] Policy violation detected: %s. Execution permitted in audit mode.", ec.shadowReason)
			resp.Reason = ec.shadowReason
			resp.Suggestion = GenerateSuggestion(fullCommand, executable, ec.shadowReason)
		}
		ec.exit(resp, 0)
		return
	}

	// 5. Pre-Execution Checkpoint for mutating commands (BAP-538)
	if !ec.decisionOnly {
		_, _ = snapshot.CreateCheckpoint(ec.sessionID, fullCommand, nil)
	}

	// 6. Execute sandboxed command with process supervision & ancestry tracking (BAP-534)
	execRes := sandbox.RunSandboxedCommandWithDetails(fullCommand)
	ec.parentPID = execRes.ParentPID
	ec.processPID = execRes.ProcessPID
	ec.processTree = execRes.ProcessTree
	output, exitCode, execErr := execRes.Output, execRes.ExitCode, execRes.Error

	resp := types.ExecResponse{
		Allowed:        true,
		Output:         output,
		ExitCode:       exitCode,
		Mode:           ec.enforcementMode,
		StepUpDecision: ec.stepUpDecision,
	}
	if ec.stepUpDecision != "" {
		switch ec.stepUpDecision {
		case "approve_once":
			resp.Warning = fmt.Sprintf("[STEP-UP AUTHORIZED] Human operator authorized one-time execution for %q.", fullCommand)
		case "session_trust":
			resp.Warning = fmt.Sprintf("[STEP-UP AUTHORIZED: SESSION TRUST] Human operator granted session trust for %q in session %s.", executable, ec.sessionID)
		case "project_trust":
			resp.Warning = fmt.Sprintf("[STEP-UP AUTHORIZED: PROJECT TRUST] Human operator granted persistent project trust for workspace %s.", authz.GetWorkspaceRoot())
		case "global_trust":
			resp.Warning = fmt.Sprintf("[STEP-UP AUTHORIZED: GLOBAL TRUST] Human operator granted persistent global trust.")
		}
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

func checkContentPinning(ec *execContext, skillName string) (string, error) {
	manifestPath := pinning.LocalManifestPath()
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifestPath = pinning.DefaultManifestPath()
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			return "", nil // No pinning manifest installed on workstation yet
		}
	}

	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil || manifest == nil || len(manifest.Assets) == 0 {
		return "", nil
	}

	// 1. If explicit skill was declared, verify it if within agent scope
	if skillName != "" {
		skillKey := skillName
		if !strings.HasPrefix(skillKey, "skill:") {
			skillKey = "skill:" + skillName
		}
		res := manifest.VerifyAsset(skillKey)
		if res.Asset.ID != "" && pinning.IsAssetInAgentScope(res.Asset.AgentScope, ec.source) {
			if !res.Matches {
				return res.CurrentHash, fmt.Errorf("declaring skill %q failed content attestation: %s", skillName, res.Error)
			}
			return res.Asset.ExpectedHash, nil
		}
	}

	// 2. Check if the executed command directly references any pinned file scoped to this agent
	cleanCmd := strings.ToLower(ec.fullCommand)
	var matchedHash string
	for _, a := range manifest.Assets {
		if !pinning.IsAssetInAgentScope(a.AgentScope, ec.source) {
			continue
		}
		baseName := strings.ToLower(filepath.Base(a.Path))
		cleanAssetPath := strings.ToLower(filepath.ToSlash(a.Path))
		if strings.Contains(cleanCmd, baseName) || strings.Contains(cleanCmd, cleanAssetPath) {
			res := manifest.VerifyAsset(a.ID)
			if !res.Matches {
				return res.CurrentHash, fmt.Errorf("referenced asset %s (%s) has drifted: %s", a.ID, a.Path, res.Error)
			}
			matchedHash = a.ExpectedHash
		}
	}

	// 3. Fast verify workspace-level skill files registered in manifest for this agent scope
	for _, a := range manifest.Assets {
		if a.AssetType == "skill" {
			if !pinning.IsAssetInAgentScope(a.AgentScope, ec.source) {
				continue
			}
			res := manifest.VerifyAsset(a.ID)
			if !res.Matches {
				return res.CurrentHash, fmt.Errorf("active skill %s on disk has drifted: %s", a.ID, res.Error)
			}
		}
	}

	// 4. Verify system prompt / instruction file for the active agent
	for _, a := range manifest.Assets {
		if a.AssetType == "prompt" {
			// Enforce if scoped specifically to this agent or global policy.cedar
			if pinning.IsAssetInAgentScope(a.AgentScope, ec.source) {
				// Only verify if base name is referenced or if it's the primary instruction file for this agent
				canon := pinning.NormalizeAgentName(ec.source)
				base := strings.ToLower(filepath.Base(a.Path))
				isPrimaryPrompt := (canon == "antigravity" && base == "gemini.md") ||
					(canon == "claude-code" && base == "claude.md") ||
					(canon == "copilot" && base == "agents.md") ||
					base == "policy.cedar"
				if isPrimaryPrompt {
					res := manifest.VerifyAsset(a.ID)
					if !res.Matches {
						return res.CurrentHash, fmt.Errorf("instruction/policy file %s on disk has drifted from pinned hash: %s", a.ID, res.Error)
					}
				}
			}
		}
	}

	return matchedHash, nil
}
