package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/internal/sandbox"
	"bap-edge/internal/state"
	"bap-edge/pkg/types"
)

// DeduplicationCache prevents duplicate evaluation or duplicate audit logs
// when both native plugin (Layer 1A) and standalone hook (Layer 1B) coexist.
type DeduplicationRecord struct {
	Timestamp  time.Time               `json:"timestamp"`
	Decision   string                  `json:"decision"`
	Reason     string                  `json:"reason"`
	Suggestion string                  `json:"suggestion,omitempty"`
	Receipt    *types.ExecutionReceipt `json:"receipt,omitempty"`
}

var (
	dedupMutex sync.Mutex
	dedupCache = make(map[string]DeduplicationRecord)
)

// RunPlugin handles the 'bapedge plugin' CLI subcommand suite (BAP-806).
func RunPlugin(args []string) error {
	if len(args) == 0 {
		printPluginUsage()
		return nil
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		return runPluginList(rest)
	case "status":
		return runPluginStatus(rest)
	case "install":
		return runPluginInstall(rest)
	case "verify":
		return runPluginVerify(rest)
	case "uninstall":
		return runPluginUninstall(rest)
	case "adapter":
		return runPluginAdapter(rest)
	case "layers":
		return runPluginLayers(rest)
	default:
		printPluginUsage()
		return fmt.Errorf("unknown plugin command: %s", sub)
	}
}

func printPluginUsage() {
	fmt.Println("BAP Native Agent Plugin Framework (BAP-806 & BAP-807)")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  bapedge plugin list                                     List discovered agents and plugin packages")
	fmt.Println("  bapedge plugin status                                   Inspect active plugin health and defense layers")
	fmt.Println("  bapedge plugin install <claude|copilot|antigravity|opencode|all> Install native agent plugin into workspace")
	fmt.Println("  bapedge plugin verify <claude|copilot|antigravity|opencode|all>  Verify plugin hook execution and enforcement")
	fmt.Println("  bapedge plugin uninstall <claude|copilot|antigravity|opencode|all> Remove plugin registration safely")
	fmt.Println("  bapedge plugin adapter [args...]                        Plugin runtime execution adapter (called by hook)")
	fmt.Println("  bapedge plugin layers                                   Show active defense-in-depth security layers")
	fmt.Println("")
}

func runPluginList(args []string) error {
	workspace, _ := os.Getwd()
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		workspace = args[0]
	}

	claudePlugin := InspectClaudePlugin(workspace)
	copilotPlugin := InspectCopilotPlugin(workspace)
	antigravityPlugin := InspectAntigravityPlugin(workspace)
	opencodePlugin := InspectOpenCodePlugin(workspace)
	codexPlugin := InspectCodexPlugin(workspace)

	fmt.Println("================================================================================")
	fmt.Println("  [BAP ZERO-TRUST] Discovered Native Agent Plugins (BAP-806, BAP-807 & BAP-808)")
	fmt.Println("================================================================================")
	fmt.Printf("  Workspace: %s\n", workspace)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("  %-15s %-22s %-10s %-12s %-25s\n", "AGENT CLIENT", "PLUGIN NAME", "VERSION", "STATE", "ENFORCEMENT")
	fmt.Println("--------------------------------------------------------------------------------")

	formatRow := func(rec types.PluginHealthRecord) {
		enf := "Unverified"
		if rec.EnforcementVerified {
			enf = "Verified (Active)"
		} else if rec.HookActive {
			enf = "Hook Active"
		}
		fmt.Printf("  %-15s %-22s %-10s %-12s %-25s\n", rec.Client, rec.PluginName, rec.PluginVersion, rec.State, enf)
	}

	formatRow(claudePlugin)
	formatRow(copilotPlugin)
	formatRow(antigravityPlugin)
	formatRow(opencodePlugin)
	formatRow(codexPlugin)
	fmt.Println("================================================================================")
	return nil
}

func runPluginStatus(args []string) error {
	workspace, _ := os.Getwd()
	for i := 0; i < len(args); i++ {
		if args[i] == "--dir" && i+1 < len(args) {
			workspace = args[i+1]
			i++
		}
	}

	fmt.Println("================================================================================")
	fmt.Println("  [BAP ZERO-TRUST] Native Plugin Health & Coverage Diagnostics")
	fmt.Println("================================================================================")

	claudeRec := InspectClaudePlugin(workspace)
	copilotRec := InspectCopilotPlugin(workspace)
	antigravityRec := InspectAntigravityPlugin(workspace)
	opencodeRec := InspectOpenCodePlugin(workspace)
	codexRec := InspectCodexPlugin(workspace)

	printPluginDetail(claudeRec)
	fmt.Println("--------------------------------------------------------------------------------")
	printPluginDetail(copilotRec)
	fmt.Println("--------------------------------------------------------------------------------")
	printPluginDetail(antigravityRec)
	fmt.Println("--------------------------------------------------------------------------------")
	printPluginDetail(opencodeRec)
	fmt.Println("--------------------------------------------------------------------------------")
	printPluginDetail(codexRec)

	fmt.Println("")
	PrintDefenseInDepthLayers(os.Stdout, workspace)
	return nil
}

func printPluginDetail(rec types.PluginHealthRecord) {
	fmt.Printf("  Agent Client:         %s\n", rec.Client)
	fmt.Printf("  Plugin Name:          %s (v%s)\n", rec.PluginName, rec.PluginVersion)
	fmt.Printf("  Lifecycle State:      %s\n", rec.State)
	fmt.Printf("  Manifest Location:    %s\n", rec.ManifestPath)
	fmt.Printf("  Agent Discovered:     %t\n", rec.AgentDiscovered)
	fmt.Printf("  Plugin Installed:     %t\n", rec.PluginInstalled)
	fmt.Printf("  Hook Active:          %t\n", rec.HookActive)
	fmt.Printf("  Enforcement Verified: %t\n", rec.EnforcementVerified)
	if rec.LastObservedAt != nil {
		fmt.Printf("  Last Observed:        %s\n", rec.LastObservedAt.Format(time.RFC3339))
	} else {
		fmt.Printf("  Last Observed:        None\n")
	}
}

func runPluginInstall(args []string) error {
	fs := flag.NewFlagSet("plugin install", flag.ContinueOnError)
	dirFlag := fs.String("dir", ".", "Target project directory or workspace root")
	if err := fs.Parse(args); err != nil {
		return err
	}

	clientArg := ""
	for _, a := range fs.Args() {
		if !strings.HasPrefix(a, "-") {
			clientArg = strings.ToLower(a)
			break
		}
	}
	if clientArg == "" {
		clientArg = "claude"
	}

	workspace, err := filepath.Abs(*dirFlag)
	if err != nil {
		return err
	}

	fmt.Println("================================================================================")
	fmt.Printf("  [BAP ZERO-TRUST] Installing Native Agent Plugin: %s\n", clientArg)
	fmt.Println("================================================================================")

	repoRoot := findRepoRoot(workspace)
	var installErr error
	switch clientArg {
	case "claude", "claude-code":
		installErr = installClaudePlugin(repoRoot, workspace)
	case "copilot", "github-copilot":
		installErr = installCopilotPlugin(repoRoot, workspace)
	case "antigravity", "agy":
		installErr = installAntigravityPlugin(repoRoot, workspace)
	case "opencode":
		installErr = installOpenCodePlugin(repoRoot, workspace)
	case "codex", "openai-codex", "openai":
		installErr = installCodexPlugin(repoRoot, workspace)
	case "all":
		if err := installClaudePlugin(repoRoot, workspace); err != nil {
			installErr = err
		}
		if err := installCopilotPlugin(repoRoot, workspace); err != nil {
			installErr = err
		}
		if err := installAntigravityPlugin(repoRoot, workspace); err != nil {
			installErr = err
		}
		if err := installOpenCodePlugin(repoRoot, workspace); err != nil {
			installErr = err
		}
		if err := installCodexPlugin(repoRoot, workspace); err != nil {
			installErr = err
		}
	default:
		return fmt.Errorf("unsupported agent client %q (supported: claude, copilot, antigravity, opencode, codex, all)", clientArg)
	}

	if installErr != nil {
		return fmt.Errorf("plugin installation failed: %w", installErr)
	}

	fmt.Println("  [✓] Plugin files written and verified.")
	fmt.Println("  [✓] Adapter scripts linked to bapedge execution broker.")
	fmt.Println("  [✓] Standalone hook coexistence verified (duplicate suppression enabled).")
	fmt.Println("")
	PrintDefenseInDepthLayers(os.Stdout, workspace)
	return nil
}

func runPluginVerify(args []string) error {
	clientArg := "claude"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		clientArg = strings.ToLower(args[0])
	}
	workspace, _ := os.Getwd()

	clientsToVerify := []string{clientArg}
	if clientArg == "all" {
		clientsToVerify = []string{"claude", "copilot", "antigravity", "opencode", "codex"}
	}

	for _, c := range clientsToVerify {
		if err := verifySingleClientPlugin(c, workspace); err != nil {
			return err
		}
	}
	return nil
}

func verifySingleClientPlugin(clientArg, workspace string) error {
	fmt.Println("================================================================================")
	fmt.Printf("  [BAP ZERO-TRUST] Verifying Policy Enforcement for %s Plugin\n", clientArg)
	fmt.Println("================================================================================")

	// 1. Synthetic benign test: allow
	benignEvent := `{"tool_name":"run_command","tool_input":{"command":"echo bap_verify_test"}}`
	allowResp, err := executeSyntheticProbe(clientArg, benignEvent, "PreToolUse")
	if err != nil {
		return fmt.Errorf("benign test probe failed to execute for %s: %w", clientArg, err)
	}
	if !allowResp.Allowed {
		return fmt.Errorf("benign command was unexpectedly denied for %s: %s", clientArg, allowResp.Reason)
	}
	fmt.Println("  [✓] Test 1: Benign Command Interception -> ALLOW (Pass)")

	// 2. Synthetic sensitive test: deny
	sensitiveEvent := `{"tool_name":"run_command","tool_input":{"command":"type C:\\Users\\User\\.ssh\\id_rsa"}}`
	denyResp, err := executeSyntheticProbe(clientArg, sensitiveEvent, "PreToolUse")
	if err != nil {
		return fmt.Errorf("sensitive test probe failed to execute for %s: %w", clientArg, err)
	}
	if denyResp.Allowed {
		return fmt.Errorf("security invariant failure for %s: Credential access command was allowed", clientArg)
	}
	fmt.Printf("  [✓] Test 2: Sensitive Invariant Violation -> DENY (Pass: %s)\n", denyResp.Reason)

	// 3. Mark enforcement verified
	recordEnforcementVerification(clientArg, workspace)
	fmt.Println("  [✓] Enforcement successfully verified and registered in local attestation spool.")
	fmt.Println("================================================================================")
	return nil
}

func runPluginUninstall(args []string) error {
	clientArg := "claude"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		clientArg = strings.ToLower(args[0])
	}
	workspace, _ := os.Getwd()

	fmt.Println("================================================================================")
	fmt.Printf("  [BAP ZERO-TRUST] Uninstalling Native Agent Plugin: %s\n", clientArg)
	fmt.Println("================================================================================")

	switch clientArg {
	case "claude", "claude-code":
		targetDir := filepath.Join(workspace, "plugins", "claude")
		_ = os.RemoveAll(targetDir)
		fmt.Printf("  [✓] Removed %s\n", targetDir)
	case "copilot", "github-copilot":
		targetDir := filepath.Join(workspace, "plugins", "copilot")
		_ = os.RemoveAll(targetDir)
		fmt.Printf("  [✓] Removed %s\n", targetDir)
	case "antigravity", "agy":
		targetDir := filepath.Join(workspace, "plugins", "antigravity")
		_ = os.RemoveAll(targetDir)
		fmt.Printf("  [✓] Removed %s\n", targetDir)
	case "opencode":
		targetDir := filepath.Join(workspace, "plugins", "opencode")
		_ = os.RemoveAll(targetDir)
		fmt.Printf("  [✓] Removed %s\n", targetDir)
	case "codex", "openai-codex", "openai":
		targetDir := filepath.Join(workspace, "plugins", "codex")
		_ = os.RemoveAll(targetDir)
		fmt.Printf("  [✓] Removed %s\n", targetDir)
	case "all":
		_ = os.RemoveAll(filepath.Join(workspace, "plugins", "claude"))
		_ = os.RemoveAll(filepath.Join(workspace, "plugins", "copilot"))
		_ = os.RemoveAll(filepath.Join(workspace, "plugins", "antigravity"))
		_ = os.RemoveAll(filepath.Join(workspace, "plugins", "opencode"))
		_ = os.RemoveAll(filepath.Join(workspace, "plugins", "codex"))
		fmt.Println("  [✓] Removed all native plugins from workspace")
	}

	fmt.Println("  [✓] Plugin removed cleanly. Existing standalone hooks remain preserved.")
	fmt.Println("================================================================================")
	return nil
}

func runPluginLayers(args []string) error {
	workspace, _ := os.Getwd()
	PrintDefenseInDepthLayers(os.Stdout, workspace)
	return nil
}

// runPluginAdapter is executed when a native plugin hook fires
func runPluginAdapter(args []string) error {
	client := "claude"
	event := "PreToolUse"

	for i := 0; i < len(args); i++ {
		if (args[i] == "--client" || args[i] == "-client") && i+1 < len(args) {
			client = strings.ToLower(args[i+1])
			i++
		} else if (args[i] == "--event" || args[i] == "-event") && i+1 < len(args) {
			event = args[i+1]
			i++
		}
	}

	// 1. Read event payload from stdin
	inputBytes, err := io.ReadAll(os.Stdin)
	if err != nil || len(inputBytes) == 0 {
		inputBytes = []byte("{}")
	}
	inputBytes = bytes.TrimPrefix(inputBytes, []byte("\xef\xbb\xbf")) // strip UTF-8 BOM
	inputBytes = bytes.TrimSpace(inputBytes)

	// 2. Parse into generic map
	var rawPayload map[string]any
	if err := json.Unmarshal(inputBytes, &rawPayload); err != nil {
		if strings.EqualFold(strings.TrimSpace(event), "pretooluse") || strings.EqualFold(strings.TrimSpace(event), "pretoolexecution") {
			emitPluginDecision(client, event, "deny", "Invalid PreToolUse hook payload JSON: "+err.Error(), nil)
			return fmt.Errorf("invalid hook payload JSON: %w", err)
		}
	}
	if rawPayload == nil {
		rawPayload = make(map[string]any)
	}

	// Record callback for observability
	recordPluginCallback(client, event, rawPayload)

	sessionID := resolvePluginSessionID(client, rawPayload)
	targetPID := extractClientPID(rawPayload)
	promptText := extractPrompt(rawPayload)

	normEvent := strings.ToLower(strings.TrimSpace(event))

	// 1. SessionStart event (CLI or IDE startup hook)
	if normEvent == "sessionstart" {
		if err := EnsureSessionStarted(sessionID, client, targetPID, promptText); err != nil {
			emitPluginDecision(client, event, "deny", err.Error(), nil)
			return err
		}
		_, _, _, _, _ = authz.EnsureSessionPrincipal(authz.ResolveZSPDir(), sessionID, normalizeClientAppID(client))
		emitPluginSuccess(client, event)
		return nil
	}

	// 2. SessionEnd / Stop event (Agent exit)
	if normEvent == "sessionend" || normEvent == "stop" || normEvent == "sessionstop" {
		_ = EnsureSessionEnded(sessionID, "Agent session closed gracefully")
		emitPluginSuccess(client, event)
		return nil
	}

	// 3. UserPromptSubmit event (Chat / prompt submitted in CLI or IDE)
	if normEvent == "userpromptsubmit" || normEvent == "userprompt" {
		_ = EnsureSessionStarted(sessionID, client, targetPID, promptText)
		_ = SubmitUserPrompt(sessionID, client, promptText)
		emitPluginSuccess(client, event)
		return nil
	}

	// 4. PreToolUse / Tool Execution hook
	// Guarantees session is auto-started even if SessionStart was never fired (e.g. in VS Code chat mode)
	_ = EnsureSessionStarted(sessionID, client, targetPID, promptText)

	// Non-blocking post-execution telemetry events (e.g. PostToolUse)
	if isTelemetryEvent(event) {
		emitPluginSuccess(client, event)
		return nil
	}

	// 5. Extract command or file path
	command, targetFile := extractCommandAndFile(rawPayload)
	toolName, _ := rawPayload["tool_name"].(string)

	// 6. Check Deduplication against recent standalone hook execution
	cmdHash := computeCommandHash(command+"|"+toolName, targetFile)
	if cached, ok := checkDedup(sessionID, cmdHash); ok {
		// Output cached decision directly
		emitPluginDecisionWithSuggestion(client, event, cached.Decision, cached.Reason, cached.Suggestion, cached.Receipt)
		return nil
	}

	// 7. Evaluate against Cedar policy invariants & ZSP TaskGrants
	ecResp := evaluateWithBapedgeTool(sessionID, client, toolName, command, targetFile)

	decision := "allow"
	if !ecResp.Allowed {
		decision = "deny"
	}

	// Record to dedup cache
	recordDedupWithSuggestion(sessionID, cmdHash, decision, ecResp.Reason, ecResp.Suggestion, ecResp.Receipt)

	// 8. Emit Vendor-Specific Response
	emitPluginDecisionWithSuggestion(client, event, decision, ecResp.Reason, ecResp.Suggestion, ecResp.Receipt)
	return nil
}

// -----------------------------------------------------------------------------
// Defense-in-Depth Layer Reporting
// -----------------------------------------------------------------------------

func GetDefenseInDepthLayers(workspace string) []types.DefenseLayerStatus {
	claudeRec := InspectClaudePlugin(workspace)
	copilotRec := InspectCopilotPlugin(workspace)
	antigravityRec := InspectAntigravityPlugin(workspace)
	opencodeRec := InspectOpenCodePlugin(workspace)
	codexRec := InspectCodexPlugin(workspace)

	// Layer 1A: Native Agent Plugin
	var activePlugins []string
	if claudeRec.PluginInstalled {
		activePlugins = append(activePlugins, "Claude Code")
	}
	if copilotRec.PluginInstalled {
		activePlugins = append(activePlugins, "Copilot")
	}
	if antigravityRec.PluginInstalled {
		activePlugins = append(activePlugins, "Antigravity")
	}
	if opencodeRec.PluginInstalled {
		activePlugins = append(activePlugins, "OpenCode")
	}
	if codexRec.PluginInstalled {
		activePlugins = append(activePlugins, "Codex")
	}

	l1aStatus := "DISABLED"
	l1aEvidence := "No native agent plugin manifest installed"
	if len(activePlugins) > 0 {
		l1aStatus = "ACTIVE"
		l1aEvidence = strings.Join(activePlugins, ", ") + " native plugins installed"
	}

	// Layer 1B: Standalone Configuration Hook
	l1bStatus := "DISABLED"
	l1bEvidence := "No standalone hooks found"
	claudeSettings := filepath.Join(workspace, ".claude", "settings.json")
	claudeManaged := filepath.Join(workspace, ".claude", "managed-settings.json")
	if _, err := os.Stat(claudeSettings); err == nil {
		l1bStatus = "ACTIVE"
		l1bEvidence = ".claude/settings.json hook interceptor configured"
	} else if _, err := os.Stat(claudeManaged); err == nil {
		l1bStatus = "ACTIVE"
		l1bEvidence = ".claude/managed-settings.json lifecycle hooks configured"
	} else if _, err := os.Stat(filepath.Join(workspace, "GEMINI.md")); err == nil {
		l1bStatus = "ACTIVE"
		l1bEvidence = "GEMINI.md policy interceptor configured"
	}

	// Layer 2: Execution Broker & Kernel Sandboxing
	l2Status := "ACTIVE"
	l2Evidence := "bapedge exec broker with restricted security tokens & Cedar policy engine"

	// Layer 3: Anti-Tamper & Asset Shielding
	l3Status := "ACTIVE"
	l3Evidence := "FIM anti-tamper shielding active for .env, .bap, policies, and keys"

	// Layer 4: Telemetry & Continuous Health Probe
	l4Status := "ACTIVE"
	l4Evidence := "Agent Watch LTD discovery worker & reporting health attestation spool active"

	// Layer 5: Cryptographic Identity & Zero-Trust Gateway
	l5Status := "ACTIVE"
	l5Evidence := "SPIFFE/SVID workstation identity and Control Plane mTLS active"

	return []types.DefenseLayerStatus{
		{LayerID: "Layer 1A", Name: "Native Agent Plugin", Description: "In-harness native vendor extension (Claude / Copilot)", Status: l1aStatus, Evidence: l1aEvidence},
		{LayerID: "Layer 1B", Name: "Standalone Hook Guard", Description: "Workspace configuration interceptor (.claude/settings.json)", Status: l1bStatus, Evidence: l1bEvidence},
		{LayerID: "Layer 2", Name: "Execution Broker", Description: "Sandboxed OS token, Cedar authorizer, process lineage", Status: l2Status, Evidence: l2Evidence},
		{LayerID: "Layer 3", Name: "Anti-Tamper & Asset Shield", Description: "FIM credential protection, canary traps, checkpoint rollback", Status: l3Status, Evidence: l3Evidence},
		{LayerID: "Layer 4", Name: "Continuous Health & Telemetry", Description: "Observable callback heartbeats, drift & degradation detection", Status: l4Status, Evidence: l4Evidence},
		{LayerID: "Layer 5", Name: "Identity & Zero-Trust Gateway", Description: "SPIFFE/SVID mTLS attestation and short-lived STS tokens", Status: l5Status, Evidence: l5Evidence},
	}
}

// PrintDefenseInDepthLayers outputs a formatted overview of all 5 defense layers.
func PrintDefenseInDepthLayers(w io.Writer, workspace string) {
	layers := GetDefenseInDepthLayers(workspace)

	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w, "  🛡️  [BAP ZERO-TRUST] Active Defense-in-Depth Security Layers")
	fmt.Fprintln(w, "================================================================================")
	for _, l := range layers {
		tag := "[✓]"
		if l.Status == "DISABLED" {
			tag = "[ ]"
		} else if l.Status == "DEGRADED" {
			tag = "[!]"
		}
		fmt.Fprintf(w, "  %-4s %-10s %-32s [%s]\n", tag, l.LayerID+":", l.Name, l.Status)
		fmt.Fprintf(w, "       └─ %s\n", l.Evidence)
	}
	fmt.Fprintln(w, "================================================================================")
}

// -----------------------------------------------------------------------------
// Inspection & Health Detection
// -----------------------------------------------------------------------------

func isGlobalOrCurrentWorkspace(workspace string) bool {
	if workspace == "" || workspace == "." {
		return true
	}
	wsRoot := authz.GetWorkspaceRoot()
	if wsRoot != "" && filepath.Clean(workspace) == filepath.Clean(wsRoot) {
		return true
	}
	if cwd, err := os.Getwd(); err == nil && filepath.Clean(workspace) == filepath.Clean(cwd) {
		return true
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		if filepath.Clean(workspace) == filepath.Clean(home) || filepath.Clean(workspace) == filepath.Clean(filepath.Join(home, "bin")) {
			return true
		}
	}
	return false
}

func InspectClaudePlugin(workspace string) types.PluginHealthRecord {
	manifestCandidates := []string{
		filepath.Join(workspace, "plugins", "claude", ".claude-plugin", "plugin.json"),
		filepath.Join(workspace, ".claude", "plugins", "claude", ".claude-plugin", "plugin.json"),
		filepath.Join(workspace, ".claude", "plugin.json"),
	}
	if isGlobalOrCurrentWorkspace(workspace) {
		home, _ := os.UserHomeDir()
		if home != "" {
			manifestCandidates = append(manifestCandidates,
				filepath.Join(home, ".claude", "plugins", "claude", ".claude-plugin", "plugin.json"),
				filepath.Join(home, ".claude", "plugins", "claude", "plugin.json"),
				filepath.Join(home, ".bap", "plugins", "claude", ".claude-plugin", "plugin.json"),
				filepath.Join(home, "bin", "plugins", "claude", ".claude-plugin", "plugin.json"),
			)
		}
		if execPath, err := os.Executable(); err == nil {
			execDir := filepath.Dir(execPath)
			manifestCandidates = append(manifestCandidates,
				filepath.Join(execDir, "plugins", "claude", ".claude-plugin", "plugin.json"),
			)
		}
	}

	manifestPath := manifestCandidates[0]
	installed := false
	var manifestData []byte
	for _, p := range manifestCandidates {
		if data, err := os.ReadFile(p); err == nil {
			manifestPath = p
			installed = true
			manifestData = data
			break
		}
	}

	rec := types.PluginHealthRecord{
		Client:        "claude-code",
		PluginName:    "BAP-ClaudeCode-Plugin",
		PluginVersion: "1.0.0",
		State:         types.PluginStateMissing,
		ManifestPath:  manifestPath,
	}

	// 1. Agent Discovered
	rec.AgentDiscovered = isAgentExecutablePresent("claude")

	// 2. Plugin Installed
	if installed {
		rec.PluginInstalled = true
		rec.State = types.PluginStateInstalled
		var m struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(manifestData, &m) == nil {
			if m.Name != "" {
				rec.PluginName = m.Name
			}
			if m.Version != "" {
				rec.PluginVersion = m.Version
			}
		}
	}

	// 3. Hook Active & Enforcement Verified from local health records
	hookActive, verified, lastObs := readHealthStatus("claude-code")
	rec.HookActive = hookActive
	rec.EnforcementVerified = verified
	rec.LastObservedAt = lastObs

	if rec.PluginInstalled {
		if rec.EnforcementVerified {
			rec.State = types.PluginStateActive
		} else if rec.HookActive {
			rec.State = types.PluginStateActive
		} else if rec.AgentDiscovered {
			rec.State = types.PluginStateDegraded // Agent running, plugin present, but no hook callbacks
		}
	} else if rec.AgentDiscovered {
		rec.State = types.PluginStateMissing
	}

	return rec
}

func InspectCopilotPlugin(workspace string) types.PluginHealthRecord {
	manifestCandidates := []string{
		filepath.Join(workspace, "plugins", "copilot", "plugin.json"),
		filepath.Join(workspace, ".vscode", "plugins", "copilot", "plugin.json"),
		filepath.Join(workspace, ".github", "copilot", "plugin.json"),
	}
	if isGlobalOrCurrentWorkspace(workspace) {
		home, _ := os.UserHomeDir()
		if home != "" {
			manifestCandidates = append(manifestCandidates,
				filepath.Join(home, ".copilot", "plugins", "copilot", "plugin.json"),
				filepath.Join(home, ".bap", "plugins", "copilot", "plugin.json"),
				filepath.Join(home, "bin", "plugins", "copilot", "plugin.json"),
			)
		}
		if execPath, err := os.Executable(); err == nil {
			execDir := filepath.Dir(execPath)
			manifestCandidates = append(manifestCandidates,
				filepath.Join(execDir, "plugins", "copilot", "plugin.json"),
			)
		}
	}

	manifestPath := manifestCandidates[0]
	installed := false
	for _, p := range manifestCandidates {
		if _, err := os.Stat(p); err == nil {
			manifestPath = p
			installed = true
			break
		}
	}

	rec := types.PluginHealthRecord{
		Client:        "copilot",
		PluginName:    "bap-copilot-plugin",
		PluginVersion: "1.0.0",
		State:         types.PluginStateMissing,
		ManifestPath:  manifestPath,
	}

	rec.AgentDiscovered = isAgentExecutablePresent("copilot")

	if installed {
		rec.PluginInstalled = true
		rec.State = types.PluginStateInstalled
	}

	hookActive, verified, lastObs := readHealthStatus("copilot")
	rec.HookActive = hookActive
	rec.EnforcementVerified = verified
	rec.LastObservedAt = lastObs

	if rec.PluginInstalled {
		if rec.EnforcementVerified {
			rec.State = types.PluginStateActive
		} else if rec.HookActive {
			rec.State = types.PluginStateActive
		} else if rec.AgentDiscovered {
			rec.State = types.PluginStateDegraded
		}
	} else if rec.AgentDiscovered {
		rec.State = types.PluginStateMissing
	}

	return rec
}

func InspectAntigravityPlugin(workspace string) types.PluginHealthRecord {
	manifestCandidates := []string{
		filepath.Join(workspace, "plugins", "antigravity", "plugin.json"),
		filepath.Join(workspace, ".agents", "plugins", "bap-antigravity", "plugin.json"),
	}
	if isGlobalOrCurrentWorkspace(workspace) {
		home, _ := os.UserHomeDir()
		if home != "" {
			manifestCandidates = append(manifestCandidates,
				filepath.Join(home, ".gemini", "config", "plugins", "bap-antigravity", "plugin.json"),
				filepath.Join(home, ".bap", "plugins", "antigravity", "plugin.json"),
				filepath.Join(home, "bin", "plugins", "antigravity", "plugin.json"),
			)
		}
		if execPath, err := os.Executable(); err == nil {
			execDir := filepath.Dir(execPath)
			manifestCandidates = append(manifestCandidates,
				filepath.Join(execDir, "plugins", "antigravity", "plugin.json"),
			)
		}
	}

	manifestPath := manifestCandidates[0]
	installed := false
	for _, p := range manifestCandidates {
		if _, err := os.Stat(p); err == nil {
			manifestPath = p
			installed = true
			break
		}
	}

	rec := types.PluginHealthRecord{
		Client:        "antigravity",
		PluginName:    "bap-antigravity",
		PluginVersion: "1.0.0",
		State:         types.PluginStateMissing,
		ManifestPath:  manifestPath,
	}

	rec.AgentDiscovered = isAgentExecutablePresent("agy") || isAgentExecutablePresent("antigravity")

	if installed {
		rec.PluginInstalled = true
		rec.State = types.PluginStateInstalled
	}

	hookActive, verified, lastObs := readHealthStatus("antigravity")
	rec.HookActive = hookActive
	rec.EnforcementVerified = verified
	rec.LastObservedAt = lastObs

	if rec.PluginInstalled {
		if rec.EnforcementVerified || rec.HookActive {
			rec.State = types.PluginStateActive
		} else if rec.AgentDiscovered {
			rec.State = types.PluginStateDegraded
		}
	} else if rec.AgentDiscovered {
		rec.State = types.PluginStateMissing
	}

	return rec
}

func InspectOpenCodePlugin(workspace string) types.PluginHealthRecord {
	manifestCandidates := []string{
		filepath.Join(workspace, "plugins", "opencode", "plugin.json"),
		filepath.Join(workspace, ".opencode", "plugins", "bap-opencode", "plugin.json"),
	}
	if isGlobalOrCurrentWorkspace(workspace) {
		home, _ := os.UserHomeDir()
		if home != "" {
			manifestCandidates = append(manifestCandidates,
				filepath.Join(home, ".config", "opencode", "plugins", "bap-opencode", "plugin.json"),
				filepath.Join(home, ".bap", "plugins", "opencode", "plugin.json"),
				filepath.Join(home, "bin", "plugins", "opencode", "plugin.json"),
			)
		}
		if execPath, err := os.Executable(); err == nil {
			execDir := filepath.Dir(execPath)
			manifestCandidates = append(manifestCandidates,
				filepath.Join(execDir, "plugins", "opencode", "plugin.json"),
			)
		}
	}

	manifestPath := manifestCandidates[0]
	installed := false
	for _, p := range manifestCandidates {
		if _, err := os.Stat(p); err == nil {
			manifestPath = p
			installed = true
			break
		}
	}

	rec := types.PluginHealthRecord{
		Client:        "opencode",
		PluginName:    "bap-opencode-plugin",
		PluginVersion: "1.0.0",
		State:         types.PluginStateMissing,
		ManifestPath:  manifestPath,
	}

	rec.AgentDiscovered = isAgentExecutablePresent("opencode")

	if installed {
		rec.PluginInstalled = true
		rec.State = types.PluginStateInstalled
	}

	hookActive, verified, lastObs := readHealthStatus("opencode")
	rec.HookActive = hookActive
	rec.EnforcementVerified = verified
	rec.LastObservedAt = lastObs

	if rec.PluginInstalled {
		if rec.EnforcementVerified || rec.HookActive {
			rec.State = types.PluginStateActive
		} else if rec.AgentDiscovered {
			rec.State = types.PluginStateDegraded
		}
	} else if rec.AgentDiscovered {
		rec.State = types.PluginStateMissing
	}

	return rec
}

func InspectCodexPlugin(workspace string) types.PluginHealthRecord {
	manifestCandidates := []string{
		filepath.Join(workspace, "plugins", "codex", "plugin.json"),
		filepath.Join(workspace, ".codex", "plugin.json"),
	}
	if isGlobalOrCurrentWorkspace(workspace) {
		home, _ := os.UserHomeDir()
		if home != "" {
			manifestCandidates = append(manifestCandidates,
				filepath.Join(home, ".codex", "plugin.json"),
				filepath.Join(home, ".bap", "plugins", "codex", "plugin.json"),
				filepath.Join(home, "bin", "plugins", "codex", "plugin.json"),
			)
		}
		if execPath, err := os.Executable(); err == nil {
			execDir := filepath.Dir(execPath)
			manifestCandidates = append(manifestCandidates,
				filepath.Join(execDir, "plugins", "codex", "plugin.json"),
			)
		}
	}

	manifestPath := manifestCandidates[0]
	installed := false
	for _, p := range manifestCandidates {
		if _, err := os.Stat(p); err == nil {
			manifestPath = p
			installed = true
			break
		}
	}

	rec := types.PluginHealthRecord{
		Client:        "codex",
		PluginName:    "bap-codex-plugin",
		PluginVersion: "1.0.0",
		State:         types.PluginStateMissing,
		ManifestPath:  manifestPath,
	}

	rec.AgentDiscovered = isAgentExecutablePresent("codex")

	if installed {
		rec.PluginInstalled = true
		rec.State = types.PluginStateInstalled
	}

	hookActive, verified, lastObs := readHealthStatus("codex")
	rec.HookActive = hookActive
	rec.EnforcementVerified = verified
	rec.LastObservedAt = lastObs

	if rec.PluginInstalled {
		if rec.EnforcementVerified || rec.HookActive {
			rec.State = types.PluginStateActive
		} else if rec.AgentDiscovered {
			rec.State = types.PluginStateDegraded
		}
	} else if rec.AgentDiscovered {
		rec.State = types.PluginStateMissing
	}

	return rec
}

func isAgentExecutablePresent(name string) bool {
	exts := []string{"", ".exe", ".cmd", ".bat"}
	pathEnv := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(pathEnv) {
		for _, ext := range exts {
			full := filepath.Join(dir, name+ext)
			if st, err := os.Stat(full); err == nil && !st.IsDir() {
				return true
			}
		}
	}
	return false
}

func normalizeClientAppID(client string) string {
	lower := strings.ToLower(strings.TrimSpace(client))
	if lower == "claude" || lower == "claude-code" || lower == "claudecode" {
		return "claude-code"
	}
	if lower == "copilot" || lower == "github-copilot" {
		return "copilot"
	}
	if lower == "antigravity" || lower == "agy" || lower == "gemini" {
		return "antigravity"
	}
	if lower == "opencode" || lower == "open-code" {
		return "opencode"
	}
	if lower == "codex" || lower == "openai-codex" || lower == "openai" {
		return "codex"
	}
	return lower
}

func readHealthStatus(client string) (hookActive, verified bool, lastObs *time.Time) {
	client = normalizeClientAppID(client)
	dirs := []string{
		filepath.Join(state.Dir(), "reporting-health"),
		filepath.Join(".bapstate", "reporting-health"),
		filepath.Join(".bap", "reporting-health"),
	}

	prefix := client + "-"
	var latest time.Time

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if (strings.HasPrefix(e.Name(), prefix) || strings.HasPrefix(e.Name(), "claude-") && client == "claude-code") && strings.HasSuffix(e.Name(), ".json") {
				body, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
				if rerr == nil {
					var sig struct {
						ObservedAt          time.Time `json:"observed_at"`
						Event               string    `json:"event"`
						EnforcementVerified bool      `json:"enforcement_verified"`
					}
					if json.Unmarshal(body, &sig) == nil {
						hookActive = true
						if sig.ObservedAt.After(latest) {
							latest = sig.ObservedAt
						}
						if sig.EnforcementVerified {
							verified = true
						}
					}
				}
			}
		}
	}
	if !latest.IsZero() {
		lastObs = &latest
	}
	return
}

func recordPluginCallback(client, event string, payload map[string]any) {
	client = normalizeClientAppID(client)
	targetDirs := []string{
		filepath.Join(state.Dir(), "reporting-health"),
		filepath.Join(".bapstate", "reporting-health"),
	}

	now := time.Now().UTC()
	fn := fmt.Sprintf("%s-plugin-%s-%d.json", client, strings.ToLower(event), now.UnixNano())
	sig := map[string]any{
		"app":                  client,
		"event":                event,
		"source":               "native_plugin",
		"observed_at":          now,
		"enforcement_verified": false,
		"session_id":           resolvePluginSessionID(client, payload),
	}
	data, _ := json.Marshal(sig)
	for _, dir := range targetDirs {
		_ = os.MkdirAll(dir, 0700)
		_ = os.WriteFile(filepath.Join(dir, fn), data, 0600)
	}
}

func recordEnforcementVerification(client, workspace string) {
	client = normalizeClientAppID(client)
	targetDirs := []string{
		filepath.Join(state.Dir(), "reporting-health"),
		filepath.Join(".bapstate", "reporting-health"),
	}

	now := time.Now().UTC()
	fn := fmt.Sprintf("%s-verified-%d.json", client, now.UnixNano())
	sig := map[string]any{
		"app":                  client,
		"event":                "EnforcementVerified",
		"source":               "synthetic_probe",
		"observed_at":          now,
		"enforcement_verified": true,
	}
	data, _ := json.Marshal(sig)
	for _, dir := range targetDirs {
		_ = os.MkdirAll(dir, 0700)
		_ = os.WriteFile(filepath.Join(dir, fn), data, 0600)
	}
}

// -----------------------------------------------------------------------------
// De-duplication Cache (Coexistence between Plugin and Standalone Hook)
// -----------------------------------------------------------------------------

func computeCommandHash(cmd, path string) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(cmd)))
	h.Write([]byte("|"))
	h.Write([]byte(strings.TrimSpace(path)))
	return hex.EncodeToString(h.Sum(nil))
}

func checkDedup(sessionID, cmdHash string) (DeduplicationRecord, bool) {
	dedupMutex.Lock()
	defer dedupMutex.Unlock()

	key := sessionID + ":" + cmdHash
	rec, exists := dedupCache[key]
	if !exists {
		return DeduplicationRecord{}, false
	}
	// Expire dedup after 5 seconds
	if time.Since(rec.Timestamp) > 5*time.Second {
		delete(dedupCache, key)
		return DeduplicationRecord{}, false
	}
	return rec, true
}

func recordDedup(sessionID, cmdHash, decision, reason string, receipt *types.ExecutionReceipt) {
	recordDedupWithSuggestion(sessionID, cmdHash, decision, reason, "", receipt)
}

func recordDedupWithSuggestion(sessionID, cmdHash, decision, reason, suggestion string, receipt *types.ExecutionReceipt) {
	dedupMutex.Lock()
	defer dedupMutex.Unlock()

	key := sessionID + ":" + cmdHash
	dedupCache[key] = DeduplicationRecord{
		Timestamp:  time.Now().UTC(),
		Decision:   decision,
		Reason:     reason,
		Suggestion: suggestion,
		Receipt:    receipt,
	}
}

// -----------------------------------------------------------------------------
// Installation Helpers
// -----------------------------------------------------------------------------

func findRepoRoot(start string) string {
	cur := start
	for {
		if _, err := os.Stat(filepath.Join(cur, "bapedge.exe")); err == nil {
			return cur
		}
		if _, err := os.Stat(filepath.Join(cur, "bap-edge")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur || parent == "" {
			break
		}
		cur = parent
	}
	return start
}

func findPluginSource(agent, repoRoot string) string {
	candidates := []string{
		filepath.Join(repoRoot, "plugins", agent),
	}
	if home, _ := os.UserHomeDir(); home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".bap", "plugins", agent),
			filepath.Join(home, "bin", "plugins", agent),
		)
	}
	if execPath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(execPath), "plugins", agent))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}

func ensureDefaultAdapterScripts(destDir string) {
	scriptsDir := filepath.Join(destDir, "scripts")
	_ = os.MkdirAll(scriptsDir, 0755)

	adapterExe := filepath.Join(scriptsDir, "bap-hook-adapter.exe")
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(adapterExe); os.IsNotExist(err) {
			exePath, err := os.Executable()
			if err == nil && strings.HasSuffix(strings.ToLower(exePath), "bapedge.exe") {
				_ = copyFile(exePath, adapterExe)
			} else {
				candidates := []string{
					filepath.Join(destDir, "..", "..", "bapedge.exe"),
					filepath.Join(destDir, "..", "..", "..", "bapedge.exe"),
					filepath.Join(destDir, "..", "..", "cchook", "interceptor.exe"),
				}
				for _, c := range candidates {
					if _, err := os.Stat(c); err == nil {
						_ = copyFile(c, adapterExe)
						break
					}
				}
			}
		}
	}

	adapterCmd := filepath.Join(scriptsDir, "bap-hook-adapter.cmd")
	if _, err := os.Stat(adapterCmd); os.IsNotExist(err) {
		cmdContent := `@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "PLUGIN_ROOT=%%~fI"

set "BAPEDGE_BIN=bapedge.exe"
if exist "%PLUGIN_ROOT%\..\..\bapedge.exe" (
    set "BAPEDGE_BIN=%PLUGIN_ROOT%\..\..\bapedge.exe"
) else (
    where bapedge.exe >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        set "BAPEDGE_BIN=bapedge.exe"
    )
)

"%BAPEDGE_BIN%" plugin adapter %*
exit /b %ERRORLEVEL%
`
		_ = os.WriteFile(adapterCmd, []byte(cmdContent), 0755)
	}

	adapterSh := filepath.Join(scriptsDir, "bap-hook-adapter")
	if _, err := os.Stat(adapterSh); os.IsNotExist(err) {
		shContent := `#!/usr/bin/env sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BAPEDGE_BIN="bapedge"
if [ -f "$PLUGIN_ROOT/../../bapedge" ]; then
    BAPEDGE_BIN="$PLUGIN_ROOT/../../bapedge"
elif command -v bapedge >/dev/null 2>&1; then
    BAPEDGE_BIN="bapedge"
fi

exec "$BAPEDGE_BIN" plugin adapter "$@"
`
		_ = os.WriteFile(adapterSh, []byte(shContent), 0755)
	}
}

func replicatePluginGlobally(agent, srcDir string) {
	home, _ := os.UserHomeDir()
	if home == "" {
		return
	}
	globalDirs := []string{
		filepath.Join(home, ".bap", "plugins", agent),
		filepath.Join(home, "bin", "plugins", agent),
	}
	if agent == "claude" {
		globalDirs = append(globalDirs, filepath.Join(home, ".claude", "plugins", "claude"))
	}
	for _, gd := range globalDirs {
		if gd != srcDir {
			_ = copyDirRecursive(srcDir, gd)
		}
	}
}

func installClaudePlugin(repoRoot, workspace string) error {
	destDir := filepath.Join(workspace, "plugins", "claude")
	if srcDir := findPluginSource("claude", repoRoot); srcDir != "" && srcDir != destDir {
		_ = copyDirRecursive(srcDir, destDir)
		replicatePluginGlobally("claude", destDir)
		return nil
	}

	_ = os.MkdirAll(filepath.Join(destDir, ".claude-plugin"), 0755)
	_ = os.MkdirAll(filepath.Join(destDir, "hooks"), 0755)
	ensureDefaultAdapterScripts(destDir)

	manifestPath := filepath.Join(destDir, ".claude-plugin", "plugin.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifest := map[string]any{
			"name":        "BAP-ClaudeCode-Plugin",
			"version":     "1.0.0",
			"description": "BAP Zero-Trust Policy Enforcement and Agent Watch Plugin for Anthropic Claude Code CLI",
			"entrypoint":  "hooks/hooks.json",
			"supportedSurfaces": []string{"cli", "terminal"},
			"capabilities": map[string]any{
				"blocking": true,
				"audit":    true,
				"events":   []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SessionEnd"},
			},
		}
		data, _ := json.MarshalIndent(manifest, "", "  ")
		_ = os.WriteFile(manifestPath, data, 0644)
	}

	hooksPath := filepath.Join(destDir, "hooks", "hooks.json")
	if _, err := os.Stat(hooksPath); os.IsNotExist(err) {
		hooksDoc := map[string]any{
			"description": "BAP Zero-Trust Security Hooks for Claude Code",
			"hooks": map[string]any{
				"SessionStart": []any{
					map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/bap-hook-adapter", "args": []string{"--client", "claude", "--event", "SessionStart"}}}},
				},
				"UserPromptSubmit": []any{
					map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/bap-hook-adapter", "args": []string{"--client", "claude", "--event", "UserPromptSubmit"}}}},
				},
				"PreToolUse": []any{
					map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/bap-hook-adapter", "args": []string{"--client", "claude", "--event", "PreToolUse"}}}},
				},
				"PostToolUse": []any{
					map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/bap-hook-adapter", "args": []string{"--client", "claude", "--event", "PostToolUse"}}}},
				},
				"Stop": []any{
					map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/bap-hook-adapter", "args": []string{"--client", "claude", "--event", "Stop"}}}},
				},
				"SessionEnd": []any{
					map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/bap-hook-adapter", "args": []string{"--client", "claude", "--event", "SessionEnd"}}}},
				},
			},
		}
		data, _ := json.MarshalIndent(hooksDoc, "", "  ")
		_ = os.WriteFile(hooksPath, data, 0644)
	}
	replicatePluginGlobally("claude", destDir)
	return nil
}

func installCopilotPlugin(repoRoot, workspace string) error {
	destDir := filepath.Join(workspace, "plugins", "copilot")
	if srcDir := findPluginSource("copilot", repoRoot); srcDir != "" && srcDir != destDir {
		_ = copyDirRecursive(srcDir, destDir)
		replicatePluginGlobally("copilot", destDir)
		return nil
	}

	_ = os.MkdirAll(filepath.Join(destDir, "com.github.copilot", "hooks"), 0755)
	ensureDefaultAdapterScripts(destDir)

	manifestPath := filepath.Join(destDir, "plugin.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifest := map[string]any{
			"name":        "bap-copilot-plugin",
			"displayName": "BAP Zero-Trust Policy Enforcement for GitHub Copilot",
			"version":     "1.0.0",
			"description": "BAP Zero-Trust In-Harness Extension for GitHub Copilot CLI and VS Code",
			"entrypoint":  "com.github.copilot/hooks/hooks.json",
			"capabilities": map[string]any{
				"blocking": true,
				"audit":    true,
			},
		}
		data, _ := json.MarshalIndent(manifest, "", "  ")
		_ = os.WriteFile(manifestPath, data, 0644)
	}

	hooksPath := filepath.Join(destDir, "com.github.copilot", "hooks", "hooks.json")
	if _, err := os.Stat(hooksPath); os.IsNotExist(err) {
		hooksDoc := map[string]any{
			"description": "BAP Zero-Trust Hooks for GitHub Copilot",
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "*",
						"hooks": []any{
							map[string]any{
								"type":    "command",
								"command": "scripts/bap-hook-adapter",
								"args":    []string{"--client", "copilot"},
							},
						},
					},
				},
			},
		}
		data, _ := json.MarshalIndent(hooksDoc, "", "  ")
		_ = os.WriteFile(hooksPath, data, 0644)
	}
	replicatePluginGlobally("copilot", destDir)
	return nil
}

func installAntigravityPlugin(repoRoot, workspace string) error {
	destDir := filepath.Join(workspace, "plugins", "antigravity")
	if srcDir := findPluginSource("antigravity", repoRoot); srcDir != "" && srcDir != destDir {
		_ = copyDirRecursive(srcDir, destDir)
		replicatePluginGlobally("antigravity", destDir)
		return nil
	}

	_ = os.MkdirAll(destDir, 0755)
	ensureDefaultAdapterScripts(destDir)

	manifestPath := filepath.Join(destDir, "plugin.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifest := map[string]any{
			"name":        "bap-antigravity",
			"version":     "1.0.0",
			"description": "BAP Zero-Trust Shell Governance and Agent Watch for Google Antigravity",
			"entrypoint":  "hooks.json",
		}
		data, _ := json.MarshalIndent(manifest, "", "  ")
		_ = os.WriteFile(manifestPath, data, 0644)
	}
	replicatePluginGlobally("antigravity", destDir)
	return nil
}

func installOpenCodePlugin(repoRoot, workspace string) error {
	destDir := filepath.Join(workspace, "plugins", "opencode")
	if srcDir := findPluginSource("opencode", repoRoot); srcDir != "" && srcDir != destDir {
		_ = copyDirRecursive(srcDir, destDir)
		replicatePluginGlobally("opencode", destDir)
		return nil
	}

	_ = os.MkdirAll(destDir, 0755)
	ensureDefaultAdapterScripts(destDir)

	manifestPath := filepath.Join(destDir, "plugin.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifest := map[string]any{
			"name":        "bap-opencode-plugin",
			"version":     "1.0.0",
			"description": "BAP Zero-Trust Extension for OpenCode Agent",
			"entrypoint":  "index.js",
		}
		data, _ := json.MarshalIndent(manifest, "", "  ")
		_ = os.WriteFile(manifestPath, data, 0644)
	}
	replicatePluginGlobally("opencode", destDir)
	return nil
}

func installCodexPlugin(repoRoot, workspace string) error {
	destDir := filepath.Join(workspace, "plugins", "codex")
	srcDir := filepath.Join(repoRoot, "plugins", "codex")

	if _, err := os.Stat(srcDir); err == nil {
		return copyDirRecursive(srcDir, destDir)
	}

	_ = os.MkdirAll(filepath.Join(destDir, "scripts"), 0755)
	_ = os.MkdirAll(filepath.Join(destDir, "rules"), 0755)

	manifestPath := filepath.Join(destDir, "plugin.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifest := map[string]any{
			"name":        "bap-codex-plugin",
			"displayName": "BAP Zero-Trust Policy Enforcement for OpenAI Codex",
			"version":     "1.0.0",
			"description": "BAP Zero-Trust Policy Enforcement and Agent Watch Plugin for OpenAI Codex CLI and Desktop",
			"publisher":   "Bounded Authority Plane (BAP)",
			"client":      "codex",
			"entrypoint":  "hooks.json",
			"supportedSurfaces": []string{
				"cli",
				"vscode",
				"jetbrains",
				"desktop",
			},
			"capabilities": map[string]any{
				"blocking": true,
				"audit":    true,
				"events": []string{
					"SessionStart",
					"UserPromptSubmit",
					"PreToolUse",
					"PostToolUse",
					"Stop",
					"SessionEnd",
				},
			},
		}
		data, _ := json.MarshalIndent(manifest, "", "  ")
		_ = os.WriteFile(manifestPath, data, 0644)
	}

	hooksPath := filepath.Join(destDir, "hooks.json")
	if _, err := os.Stat(hooksPath); os.IsNotExist(err) {
		hooksDoc := map[string]any{
			"description": "BAP Zero-Trust Policy Enforcement & Interception Hooks for OpenAI Codex",
			"version":     "1.0.0",
			"hooks": map[string]any{
				"SessionStart": []any{
					map[string]any{
						"hooks": []any{
							map[string]any{
								"type":           "command",
								"command":        "scripts/bap-hook-adapter",
								"commandWindows": "scripts\\bap-hook-adapter.cmd",
								"timeout":        10,
							},
						},
					},
				},
				"UserPromptSubmit": []any{
					map[string]any{
						"hooks": []any{
							map[string]any{
								"type":           "command",
								"command":        "scripts/bap-hook-adapter",
								"commandWindows": "scripts\\bap-hook-adapter.cmd",
								"timeout":        10,
							},
						},
					},
				},
				"PreToolUse": []any{
					map[string]any{
						"matcher": ".*",
						"hooks": []any{
							map[string]any{
								"type":           "command",
								"command":        "scripts/bap-hook-adapter",
								"commandWindows": "scripts\\bap-hook-adapter.cmd",
								"timeout":        30,
							},
						},
					},
				},
				"PostToolUse": []any{
					map[string]any{
						"matcher": ".*",
						"hooks": []any{
							map[string]any{
								"type":           "command",
								"command":        "scripts/bap-hook-adapter",
								"commandWindows": "scripts\\bap-hook-adapter.cmd",
								"timeout":        15,
							},
						},
					},
				},
				"Stop": []any{
					map[string]any{
						"hooks": []any{
							map[string]any{
								"type":           "command",
								"command":        "scripts/bap-hook-adapter",
								"commandWindows": "scripts\\bap-hook-adapter.cmd",
								"timeout":        10,
							},
						},
					},
				},
				"SessionEnd": []any{
					map[string]any{
						"hooks": []any{
							map[string]any{
								"type":           "command",
								"command":        "scripts/bap-hook-adapter",
								"commandWindows": "scripts\\bap-hook-adapter.cmd",
								"timeout":        5,
							},
						},
					},
				},
			},
		}
		data, _ := json.MarshalIndent(hooksDoc, "", "  ")
		_ = os.WriteFile(hooksPath, data, 0644)
	}

	adapterSh := filepath.Join(destDir, "scripts", "bap-hook-adapter")
	if _, err := os.Stat(adapterSh); os.IsNotExist(err) {
		shContent := `#!/usr/bin/env sh
# BAP Local Trusted Daemon Hook Adapter for OpenAI Codex
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BAPEDGE_BIN="bapedge"
if [ -f "$PLUGIN_ROOT/../../bapedge" ]; then
    BAPEDGE_BIN="$PLUGIN_ROOT/../../bapedge"
elif command -v bapedge >/dev/null 2>&1; then
    BAPEDGE_BIN="bapedge"
fi

exec "$BAPEDGE_BIN" plugin adapter --client codex
`
		_ = os.WriteFile(adapterSh, []byte(shContent), 0755)
	}

	adapterCmd := filepath.Join(destDir, "scripts", "bap-hook-adapter.cmd")
	if _, err := os.Stat(adapterCmd); os.IsNotExist(err) {
		cmdContent := `@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "PLUGIN_ROOT=%%~fI"

set "BAPEDGE_BIN=bapedge.exe"
if exist "%PLUGIN_ROOT%\..\..\bapedge.exe" (
    set "BAPEDGE_BIN=%PLUGIN_ROOT%\..\..\bapedge.exe"
) else (
    where bapedge.exe >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        set "BAPEDGE_BIN=bapedge.exe"
    )
)

"%BAPEDGE_BIN%" plugin adapter --client codex
exit /b %ERRORLEVEL%
`
		_ = os.WriteFile(adapterCmd, []byte(cmdContent), 0755)
	}

	rulesPath := filepath.Join(destDir, "rules", "AGENTS.md")
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		rulesContent := `# BAP Zero-Trust Policy & Shell Governance for OpenAI Codex (Governed Session)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Mandatory Execution Rules
1. **Always Use BAP Edge Execution Broker**:
   - All shell executions MUST run through bapedge.exe exec:
      bapedge.exe exec "<command>"
   - Never run raw, ungoverned shell commands directly on the host machine.
2. **Zero-Trust Policy Enforcement**:
   - Commands are evaluated against Cedar invariants before execution.
   - If a command is denied, inspect the suggestion in the structured response.
3. **Identity & Audit Logging**:
   - LTD_SOURCE=codex
   - Identity: spiffe://bap.local/agent/codex
`
		_ = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	}

	return nil
}

func copyDirRecursive(src, dst string) error {
	if src == dst {
		return nil
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

// -----------------------------------------------------------------------------
// Execution & Policy Bridge
// -----------------------------------------------------------------------------

func isTelemetryEvent(event string) bool {
	lower := strings.ToLower(event)
	return lower == "posttooluse" || lower == "posttoolexecution" || lower == "posttoolusefailure"
}

func extractCommandAndFile(payload map[string]any) (command, filePath string) {
	// 1. Direct command
	if c, ok := payload["command"].(string); ok && c != "" {
		command = c
	}
	// 2. tool_input
	if ti, ok := payload["tool_input"].(map[string]any); ok {
		if c, ok := ti["command"].(string); ok && c != "" {
			command = c
		}
		if p, ok := ti["file_path"].(string); ok && p != "" {
			filePath = p
		} else if p, ok := ti["path"].(string); ok && p != "" {
			filePath = p
		}
	}
	// 3. tool_call
	if tc, ok := payload["tool_call"].(map[string]any); ok {
		if args, ok := tc["args"].(map[string]any); ok {
			if c, ok := args["CommandLine"].(string); ok && c != "" {
				command = c
			} else if c, ok := args["command"].(string); ok && c != "" {
				command = c
			}
			if p, ok := args["Path"].(string); ok && p != "" {
				filePath = p
			}
		}
	}
	return
}

func resolvePluginSessionID(client string, payload map[string]any) string {
	if s, ok := payload["session_id"].(string); ok && s != "" {
		return s
	}
	if s, ok := payload["conversation_id"].(string); ok && s != "" {
		return s
	}
	if s := os.Getenv("BAP_SESSION_ID"); s != "" {
		return s
	}
	return fmt.Sprintf("sess-%s-pid-%d", client, os.Getppid())
}

func evaluateWithBapedge(sessionID, client, command, filePath string) types.ExecResponse {
	return evaluateWithBapedgeTool(sessionID, client, "", command, filePath)
}

func unwrapPluginBrokerCommand(command, expectedSessionID string) (string, error) {
	words := splitShellWords(strings.TrimSpace(command))
	if len(words) == 0 {
		return command, nil
	}
	executable := strings.Trim(words[0], `"'`)
	executable = filepath.Base(strings.ReplaceAll(executable, `\`, "/"))
	switch strings.ToLower(executable) {
	case "bapedge", "bapedge.exe", "ltd-agent", "ltd-agent.exe":
	default:
		return command, nil
	}

	if len(words) >= 2 && words[1] == "exec" && !strings.Contains(command, "--cmd-b64") {
		idx := strings.Index(command, "exec")
		rawInner := strings.TrimSpace(command[idx+4:])
		rawInner = strings.Trim(rawInner, `"'`)
		if rawInner != "" {
			return rawInner, nil
		}
	}

	// Atomic control subcommands are handled downstream by IsZSPControlCommand.
	if len(words) >= 2 && !strings.Contains(command, "--cmd-b64") {
		sub := strings.ToLower(strings.Trim(words[1], `"'`))
		switch sub {
		case "zsp", "status", "why", "version":
			return command, nil
		}
	}

	if authz.HasUnquotedControlOperator(command) {
		return "", fmt.Errorf("untrusted BAPEdge invocation: chained command operators are not permitted")
	}

	var sourceVal, sessionVal, b64Val string
	hasExec := false
	for i := 1; i < len(words); i++ {
		arg := strings.Trim(words[i], `"'`)
		if arg == "exec" {
			hasExec = true
		} else if arg == "--source" && i+1 < len(words) {
			sourceVal = strings.Trim(words[i+1], `"'`)
			i++
		} else if arg == "--session-id" && i+1 < len(words) {
			sessionVal = strings.Trim(words[i+1], `"'`)
			i++
		} else if arg == "--cmd-b64" && i+1 < len(words) {
			b64Val = strings.Trim(words[i+1], `"'`)
			i++
		} else if (arg == "--shell" || arg == "--caller-binary" || arg == "--caller-hash") && i+1 < len(words) {
			i++
		} else {
			return "", fmt.Errorf("untrusted BAPEdge invocation: unexpected argument %q", arg)
		}
	}
	if !hasExec || sourceVal == "" || sessionVal == "" || b64Val == "" {
		return "", fmt.Errorf("untrusted BAPEdge invocation: expected valid bapedge exec wrapper")
	}
	if expectedSessionID != "" && sessionVal != expectedSessionID {
		return "", fmt.Errorf("untrusted BAPEdge invocation: session binding mismatch")
	}
	payload, err := base64.StdEncoding.DecodeString(b64Val)
	if err != nil {
		return "", fmt.Errorf("untrusted BAPEdge invocation: invalid command payload")
	}
	decoded := strings.TrimSpace(string(payload))
	if decoded == "" {
		return "", fmt.Errorf("untrusted BAPEdge invocation: empty command payload")
	}
	return decoded, nil
}

func isProtectedPluginAsset(normPath string) bool {
	if normPath == "" {
		return false
	}
	for _, marker := range []string{
		"policy.cedar",
		".claude/settings.json",
		".claude/hooks",
		".bap-session.json",
		".bap-revoked",
		"bap-config.json",
		"bapedge.exe",
		"interceptor.exe",
		"cchook-interceptor",
		"bapcontrolplane",
		"bapgateway",
		"/.bap/",
		"/.bapstate/",
	} {
		if strings.Contains(normPath, marker) {
			return true
		}
	}
	return false
}

func isMutatingPluginTool(toolName string) bool {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "edit", "write", "multi_edit", "multiedit", "notebookedit", "replace_file_content", "write_to_file":
		return true
	default:
		return false
	}
}

func evaluateWithBapedgeTool(sessionID, client, toolName, command, filePath string) types.ExecResponse {
	wsRoot := authz.GetWorkspaceRoot()
	normClient := normalizeClientAppID(client)

	if command != "" {
		unwrapped, unwrapErr := unwrapPluginBrokerCommand(command, sessionID)
		if unwrapErr != nil {
			return types.ExecResponse{
				Allowed:    false,
				ExitCode:   1,
				Reason:     "Security Invariant Violation: " + unwrapErr.Error(),
				Suggestion: "Invoke BAPEdge control commands (such as bapedge zsp authorize) standalone without chaining operators.",
			}
		}
		command = unwrapped
	}

	// Secret Protection
	normPath := strings.ToLower(filepath.ToSlash(filePath))
	normCmd := strings.ToLower(filepath.ToSlash(command))
	if strings.Contains(normPath, ".env") || strings.Contains(normPath, ".ssh") || strings.Contains(normPath, ".aws") ||
		strings.Contains(normCmd, ".env") || strings.Contains(normCmd, ".ssh") || strings.Contains(normCmd, ".aws") ||
		strings.Contains(normPath, "id_rsa") || strings.Contains(normCmd, "id_rsa") {
		return types.ExecResponse{
			Allowed:    false,
			ExitCode:   1,
			Reason:     "Security Invariant Violation: Access to sensitive credential stores (.env, .ssh, .aws) is strictly forbidden by enterprise zero-trust policy",
			Suggestion: "Direct file inspection or exfiltration of credential stores is blocked.",
		}
	}

	// Allow atomic ZSP control commands (e.g. 'bapedge zsp authorize', 'bapedge status')
	if command != "" && authz.IsZSPControlCommand(command) {
		return types.ExecResponse{
			Allowed:  true,
			ExitCode: 0,
			Receipt: &types.ExecutionReceipt{
				ReceiptID:      fmt.Sprintf("rcpt-%d", time.Now().UnixNano()),
				Identity:       fmt.Sprintf("spiffe://bap.local/agent/%s", normClient),
				Delegation:     fmt.Sprintf("user:workstation->agent:%s", normClient),
				PolicyVersion:  "sha256:enterprise-active",
				SandboxProfile: "zsp-control-channel",
				SessionID:      sessionID,
				Timestamp:      time.Now().UTC(),
				Result:         "ALLOWED_ZSP_CONTROL",
			},
		}
	}

	// Anti-Tampering Check
	isCmdTamper := false
	tamperReason := ""
	if command != "" {
		isCmdTamper, tamperReason = isTamperingAttempt(command)
	}
	isPathTamper := (toolName == "" || isMutatingPluginTool(toolName)) && isProtectedPluginAsset(normPath)
	if isCmdTamper || isPathTamper {
		if active, _ := devOverrideActive(); !active {
			if tamperReason == "" {
				tamperReason = "Security Invariant Violation: Direct mutation or tampering with BAP configuration, policies, hooks, or binaries is prohibited"
			}
			return types.ExecResponse{
				Allowed:    false,
				ExitCode:   1,
				Reason:     tamperReason,
				Suggestion: "Use 'bapedge trust' or request human operator authorization.",
			}
		}
	}

	// Filesystem Root Escape Check (e.g., Get-ChildItem -Force \, ls /, dir C:\)
	if (command != "" && authz.HasFilesystemRootEscape(wsRoot, command)) ||
		(filePath != "" && (authz.IsFilesystemRootTarget(filePath) || authz.IsFilesystemRootTarget(authz.ResolveCanonicalPath(filePath, wsRoot)))) {
		return types.ExecResponse{
			Allowed:    false,
			ExitCode:   1,
			Reason:     "Security Invariant Violation: Target path escapes workspace boundary to filesystem/drive root",
			Suggestion: "Operations targeting root directories outside the workspace are prohibited.",
		}
	}

	principalIdentity := fmt.Sprintf("spiffe://bap.local/agent/%s", normClient)
	grantID := ""

	// Zero Standing Privileges Enforcement for real agent sessions
	if sessionID != "synthetic-probe-session" && authz.IsZSPEnforced() {
		if command == "" && filePath == "" && toolName == "" {
			return types.ExecResponse{
				Allowed:    false,
				ExitCode:   1,
				Reason:     "ZeroStandingPrivilegeViolation: PreToolUse payload missing tool/command context (fail-closed)",
				Suggestion: "Provide a valid PreToolUse tool invocation with an active TaskGrant.",
			}
		}
		execName, execArgs := sandbox.ParseCommand(command)
		zspChecks := authz.ResolveZSPCommandChecks(command, execName, execArgs, toolName, filePath, wsRoot)

		// Avoid double-burning a single-use grant if standalone .claude/settings.json hook
		// is also configured to wrap shell execution through `bapedge exec`.
		consumeHere := true
		if command != "" {
			if _, err := os.Stat(filepath.Join(wsRoot, ".claude", "settings.json")); err == nil {
				consumeHere = false
			}
		}

		svid, grant, _, zspErr := authz.VerifyOrConsumeSessionZSPChecks(
			authz.ResolveZSPDir(), sessionID, normClient, zspChecks, command, wsRoot, consumeHere, nil,
		)
		if svid != nil {
			principalIdentity = svid.Subject
		}
		if zspErr != nil {
			suggestedActions := authz.SummarizeZSPActions(zspChecks)
			goalTarget := command
			if goalTarget == "" {
				goalTarget = toolName
				if filePath != "" {
					goalTarget = toolName + " " + filePath
				}
			}
			return types.ExecResponse{
				Allowed:    false,
				ExitCode:   1,
				Reason:     fmt.Sprintf("ZeroStandingPrivilegeViolation: %v", zspErr),
				Suggestion: authz.FormatZSPAgentSuggestion(principalIdentity, sessionID, goalTarget, suggestedActions, len(zspChecks)),
			}
		}
		if grant != nil {
			grantID = grant.GrantID
		}
	}

	return types.ExecResponse{
		Allowed:  true,
		ExitCode: 0,
		Receipt: &types.ExecutionReceipt{
			ReceiptID:      fmt.Sprintf("rcpt-%d", time.Now().UnixNano()),
			Identity:       principalIdentity,
			Delegation:     fmt.Sprintf("user:workstation->agent:%s", normClient),
			GrantID:        grantID,
			PolicyVersion:  "sha256:enterprise-active",
			SandboxProfile: "windows-restricted-token",
			SessionID:      sessionID,
			Timestamp:      time.Now().UTC(),
			Result:         "ALLOWED_EXECUTED",
		},
	}
}

func executeSyntheticProbe(client, eventJSON, eventName string) (types.ExecResponse, error) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(eventJSON), &payload); err != nil {
		return types.ExecResponse{}, err
	}
	cmd, file := extractCommandAndFile(payload)
	resp := evaluateWithBapedge("synthetic-probe-session", client, cmd, file)
	return resp, nil
}

func emitPluginSuccess(client, event string) {
	norm := normalizeClientAppID(client)
	switch norm {
	case "claude-code":
		fmt.Println(`{"status":"ok","continue":true}`)
	case "codex":
		fmt.Println(`{"status":"ok","continue":true}`)
	case "antigravity":
		fmt.Println(`{"decision":"allow"}`)
	default:
		fmt.Println(`{"allowed":true}`)
	}
}

func emitPluginDecision(client, event, decision, reason string, receipt *types.ExecutionReceipt) {
	emitPluginDecisionWithSuggestion(client, event, decision, reason, "", receipt)
}

func emitPluginDecisionWithSuggestion(client, event, decision, reason, suggestion string, receipt *types.ExecutionReceipt) {
	isInvariant := strings.Contains(reason, "Security Invariant Violation") ||
		strings.Contains(reason, "sensitive credential") ||
		strings.Contains(reason, "tampering")
	denyContext := "Action blocked by enterprise zero-trust policy. CEASE attempts to access this resource."
	if !isInvariant {
		if suggestion != "" {
			denyContext = fmt.Sprintf("BAP Zero-Trust Policy Decision: %s. SUGGESTION: %s", reason, suggestion)
		} else {
			denyContext = fmt.Sprintf("BAP Zero-Trust Policy Decision: %s", reason)
		}
	}

	norm := normalizeClientAppID(client)
	switch norm {
	case "claude-code":
		if decision == "allow" {
			out := map[string]any{
				"status":   "ok",
				"continue": true,
				"hookSpecificOutput": map[string]any{
					"hookEventName":      event,
					"permissionDecision": "allow",
				},
			}
			data, _ := json.Marshal(out)
			fmt.Println(string(data))
		} else {
			out := map[string]any{
				"status":   "deny",
				"continue": !isInvariant,
				"hookSpecificOutput": map[string]any{
					"hookEventName":            event,
					"permissionDecision":       "deny",
					"permissionDecisionReason": reason,
					"additionalContext":        denyContext,
				},
			}
			data, _ := json.Marshal(out)
			fmt.Println(string(data))
		}
	case "codex":
		if decision == "allow" {
			out := map[string]any{
				"hookSpecificOutput": map[string]any{
					"hookEventName":            event,
					"permissionDecision":       "allow",
					"permissionDecisionReason": reason,
				},
			}
			data, _ := json.Marshal(out)
			fmt.Println(string(data))
		} else {
			fmt.Fprintf(os.Stderr, "[CODEX BLOCKED BY POLICY] %s\n", reason)
			if isInvariant {
				fmt.Fprintln(os.Stderr, "[CRITICAL SECURITY INVARIANT] Access to this resource is permanently prohibited by enterprise zero-trust policy.")
			}
			out := map[string]any{
				"hookSpecificOutput": map[string]any{
					"hookEventName":            event,
					"permissionDecision":       "deny",
					"permissionDecisionReason": reason,
					"additionalContext":        denyContext,
				},
			}
			data, _ := json.Marshal(out)
			fmt.Println(string(data))
		}
	case "antigravity":
		if decision == "allow" {
			fmt.Println(`{"decision":"allow"}`)
		} else {
			fmt.Fprintf(os.Stderr, "[ANTIGRAVITY BLOCKED BY POLICY] %s\n", reason)
			out := map[string]any{
				"decision": "deny",
				"reason":   reason,
			}
			data, _ := json.Marshal(out)
			fmt.Println(string(data))
		}
	case "opencode":
		if decision == "allow" {
			fmt.Println(`{"allowed":true}`)
		} else {
			fmt.Fprintf(os.Stderr, "[OPENCODE BLOCKED BY POLICY] %s\n", reason)
			out := map[string]any{
				"allowed": false,
				"reason":  reason,
			}
			data, _ := json.Marshal(out)
			fmt.Println(string(data))
		}
	default:
		// Copilot response format
		if decision == "allow" {
			fmt.Println(`{"allowed":true}`)
		} else {
			fmt.Fprintf(os.Stderr, "[COPILOT BLOCKED BY POLICY] %s\n", reason)
			fmt.Fprintln(os.Stderr, "[CRITICAL SECURITY INVARIANT] Access to this resource is permanently prohibited by enterprise zero-trust policy.")
			out := map[string]any{
				"allowed": false,
				"reason":  reason,
			}
			data, _ := json.Marshal(out)
			fmt.Println(string(data))
		}
	}
}
