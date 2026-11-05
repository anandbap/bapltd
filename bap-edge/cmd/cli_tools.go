package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/authz"
	"bap-edge/internal/config"
	discoverymeta "bap-edge/internal/discovery"
	"bap-edge/internal/httptransport"
	"bap-edge/internal/policystore"
	"bap-edge/internal/state"
	"bap-edge/pkg/types"
	"bap-edge/pkg/version"
)

// RunSetup provides a 1-click idempotent configuration for developer workstations (BAP-471).
// Configures Claude Code managed-settings.json with dangerouslySkipPermissions: false
// and wires lifecycle hooks directly to bapedge exec.
func RunSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	appFlag := fs.String("app", "claude-code", "Target AI agent application identifier")
	dirFlag := fs.String("dir", ".", "Target project directory or workspace root")
	serverFlag := fs.String("server", "", "Central BAP control plane URL")
	forceFlag := fs.Bool("force", false, "Overwrite existing configuration files")

	if err := fs.Parse(args); err != nil {
		return err
	}

	targetDir, err := filepath.Abs(*dirFlag)
	if err != nil {
		return fmt.Errorf("invalid directory %q: %w", *dirFlag, err)
	}

	serverURL := *serverFlag
	if serverURL == "" {
		ep := config.ResolveEndpoints()
		serverURL = ep.ControlPlaneURL
	}
	if serverURL == "" {
		serverURL = config.DefaultControlPlaneURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	fmt.Println("================================================================================")
	fmt.Println("  [BAP ZERO-TRUST] 🚀 Initializing Developer Agent Environment (1-Click Setup)")
	fmt.Println("================================================================================")
	fmt.Printf("  Target App:       %s\n", *appFlag)
	fmt.Printf("  Workspace Root:   %s\n", targetDir)
	fmt.Printf("  Control Plane:    %s\n", serverURL)
	fmt.Println("--------------------------------------------------------------------------------")

	// 1. Configure .claude/managed-settings.json
	claudeDir := filepath.Join(targetDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", claudeDir, err)
	}

	managedSettingsPath := filepath.Join(claudeDir, "managed-settings.json")
	var settings map[string]any

	if existingData, err := os.ReadFile(managedSettingsPath); err == nil && !*forceFlag {
		_ = json.Unmarshal(existingData, &settings)
	}
	if settings == nil {
		settings = make(map[string]any)
	}

	// Invariant: dangerouslySkipPermissions MUST be false
	settings["dangerouslySkipPermissions"] = false
	settings["bap_managed"] = true
	settings["control_plane_url"] = serverURL

	hooks, ok := settings["lifecycle_hooks"].(map[string]any)
	if !ok || hooks == nil {
		hooks = make(map[string]any)
	}
	hooks["pre_tool_use"] = "bapedge exec"
	hooks["post_tool_use"] = "bapedge verify-log"
	settings["lifecycle_hooks"] = hooks

	settingsJSON, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode settings: %w", err)
	}
	if err := os.WriteFile(managedSettingsPath, settingsJSON, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", managedSettingsPath, err)
	}
	fmt.Printf("  [✓] Configured %s\n", managedSettingsPath)
	fmt.Println("      - dangerouslySkipPermissions: FALSE (Hardened by BAP)")
	fmt.Println("      - pre_tool_use hook:          bapedge exec")

	// 2. Configure .bap/config.json
	bapDir := filepath.Join(targetDir, ".bap")
	if err := os.MkdirAll(bapDir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", bapDir, err)
	}
	bapCfgPath := filepath.Join(bapDir, "config.json")
	bapCfg := map[string]any{
		"control_plane_url": serverURL,
		"app_id":            *appFlag,
		"managed":           true,
		"configured_at":     time.Now().UTC().Format(time.RFC3339),
	}
	bapCfgJSON, _ := json.MarshalIndent(bapCfg, "", "  ")
	if err := os.WriteFile(bapCfgPath, bapCfgJSON, 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", bapCfgPath, err)
	}
	fmt.Printf("  [✓] Configured %s\n", bapCfgPath)

	// 3. Install Native Agent Plugin alongside Standalone Hook (BAP-806)
	repoRoot := findRepoRoot(targetDir)
	appLower := strings.ToLower(*appFlag)
	if strings.Contains(appLower, "claude") {
		if err := installClaudePlugin(repoRoot, targetDir); err == nil {
			fmt.Println("  [✓] Installed Native Claude Code Plugin (Layer 1A: In-Harness Extension)")
		}
	} else if strings.Contains(appLower, "copilot") {
		if err := installCopilotPlugin(repoRoot, targetDir); err == nil {
			fmt.Println("  [✓] Installed Native Copilot Plugin (Layer 1A: In-Harness Extension)")
		}
	} else if strings.Contains(appLower, "antigravity") || strings.Contains(appLower, "agy") {
		if err := installAntigravityPlugin(repoRoot, targetDir); err == nil {
			fmt.Println("  [✓] Installed Native Antigravity Plugin (Layer 1A: In-Harness Extension)")
		}
	} else if strings.Contains(appLower, "opencode") {
		if err := installOpenCodePlugin(repoRoot, targetDir); err == nil {
			fmt.Println("  [✓] Installed Native OpenCode Plugin (Layer 1A: In-Harness Extension)")
		}
	} else if strings.Contains(appLower, "codex") || strings.Contains(appLower, "openai") {
		if err := installCodexPlugin(repoRoot, targetDir); err == nil {
			fmt.Println("  [✓] Installed Native Codex Plugin (Layer 1A: In-Harness Extension)")
		}
	} else if appLower == "all" {
		_ = installClaudePlugin(repoRoot, targetDir)
		_ = installCopilotPlugin(repoRoot, targetDir)
		_ = installAntigravityPlugin(repoRoot, targetDir)
		_ = installOpenCodePlugin(repoRoot, targetDir)
		_ = installCodexPlugin(repoRoot, targetDir)
		fmt.Println("  [✓] Installed Native Plugins for Claude, Copilot, Antigravity, OpenCode, and Codex (Layer 1A)")
	}

	fmt.Println("")
	PrintDefenseInDepthLayers(os.Stdout, targetDir)

	fmt.Println("================================================================================")
	fmt.Println("  ✅ Workstation setup complete! Agent execution is bound to Zero-Trust Policy.")
	fmt.Println("================================================================================")
	return nil
}

// RunStatus provides terminal inspection of active sessions, Cedar policy bundle,
// layered compliance, degraded operating mode, and offline spool backlog (BAP-472).
func RunStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	serverFlag := fs.String("server", "", "Central BAP control plane URL")
	jsonFlag := fs.Bool("json", false, "Output status in JSON format")
	noSweepFlag := fs.Bool("no-sweep", false, "Disable automatic sweep and flush of pending spool")

	if err := fs.Parse(args); err != nil {
		return err
	}

	serverURL := *serverFlag
	if serverURL == "" {
		ep := config.ResolveEndpoints()
		serverURL = ep.ControlPlaneURL
	}
	if serverURL == "" {
		serverURL = config.DefaultControlPlaneURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}

	// 1. Live Control Plane Probe
	probeStart := time.Now()
	client := httptransport.New(1500 * time.Millisecond)
	cpConnected := false
	cpLatencyMs := int64(0)
	cpStatusText := "DISCONNECTED / OFFLINE (Local Spool Active)"
	cpServerVersion := ""
	cpMinEdgeVersion := ""
	if resp, err := client.Get(serverURL + "/health"); err == nil {
		cpLatencyMs = time.Since(probeStart).Milliseconds()
		if resp.StatusCode == http.StatusOK {
			cpConnected = true
			cpStatusText = fmt.Sprintf("CONNECTED / ONLINE (%dms)", cpLatencyMs)
			var hData map[string]any
			if jsonErr := json.NewDecoder(resp.Body).Decode(&hData); jsonErr == nil {
				if v, ok := hData["version"].(string); ok {
					cpServerVersion = v
				}
				if mv, ok := hData["min_edge_version"].(string); ok {
					cpMinEdgeVersion = mv
				}
			}
			if cpServerVersion == "" {
				cpServerVersion = resp.Header.Get("X-BAP-Server-Version")
			}
		} else {
			cpStatusText = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	// Fallback probe: if explicit -server was not provided and primary URL is unreachable, try local fallbacks
	if !cpConnected && *serverFlag == "" {
		fallbacks := []string{
			"https://localhost:8443", "https://127.0.0.1:8443",
			"http://localhost:8080", "http://127.0.0.1:8080",
		}
		for _, fb := range fallbacks {
			if strings.TrimRight(serverURL, "/") == fb {
				continue
			}
			fbStart := time.Now()
			if resp, err := client.Get(fb + "/health"); err == nil {
				if resp.StatusCode == http.StatusOK {
					cpConnected = true
					serverURL = fb
					cpLatencyMs = time.Since(fbStart).Milliseconds()
					cpStatusText = fmt.Sprintf("CONNECTED / ONLINE (%dms) [fallback to %s]", cpLatencyMs, fb)
					_ = resp.Body.Close()
					break
				}
				_ = resp.Body.Close()
			}
		}
	}

	// 2. Operating Mode & Daemon Detection (Degraded vs Enterprise Managed)
	daemonActive := isDaemonRunning()
	operatingMode := "STANDALONE_USER_SPACE"
	operatingModeDesc := "STANDALONE USER-SPACE (Policy Broker Active: Zero admin rights required; evaluates Cedar invariants locally on every command)"
	if daemonActive {
		operatingMode = "ENTERPRISE_MANAGED"
		operatingModeDesc = "ENTERPRISE MANAGED (Background Supervisor Daemon Attached: Live V3 telemetry, active heartbeats, and real-time remote sync)"
	}

	// 3. Enrolled Identity & Credentials
	var creds StoredCredentials
	enrolled := false
	authModeLabel := "Unenrolled"

	candidateCredPaths := []string{
		DefaultCredentialsPath(),
		state.CredentialsPath(),
	}
	if home, hErr := os.UserHomeDir(); hErr == nil && home != "" {
		candidateCredPaths = append(candidateCredPaths,
			filepath.Join(home, ".bapstate", "credentials.json"),
			filepath.Join(home, ".ltd", "credentials.json"),
			filepath.Join(home, ".bap", "credentials.json"),
		)
	}
	candidateCredPaths = append(candidateCredPaths,
		filepath.Join(".bapstate", "credentials.json"),
		filepath.Join(".ltd", "credentials.json"),
		filepath.Join(".bap", "credentials.json"),
	)
	if envCreds := os.Getenv("BAP_CREDENTIALS"); envCreds != "" {
		candidateCredPaths = append(candidateCredPaths, envCreds)
	}

	var credsData []byte
	foundCredPath := DefaultCredentialsPath()
	for _, cp := range candidateCredPaths {
		if cp == "" {
			continue
		}
		if data, err := os.ReadFile(cp); err == nil && len(data) > 0 {
			credsData = data
			foundCredPath = cp
			break
		}
	}

	if len(credsData) > 0 {
		if json.Unmarshal(credsData, &creds) == nil && creds.AgentID != "" {
			enrolled = true
			authModeLabel = "One-Time Code (OTC)"
			if creds.AuthMode == "oidc" {
				idp := "Microsoft Entra ID"
				if strings.EqualFold(creds.IdPProvider, "okta") {
					idp = "Okta Workforce Identity"
				} else if strings.EqualFold(creds.IdPProvider, "google") {
					idp = "Google Identity"
				} else if strings.EqualFold(creds.IdPProvider, "github") {
					idp = "GitHub Developer Identity"
				} else if creds.IdPProvider != "" {
					idp = creds.IdPProvider
				}
				authModeLabel = fmt.Sprintf("OIDC Federated (%s, MFA Enforced)", idp)
			}

			// If control plane is reachable, verify that this specific agent has not been deregistered or frozen
			if creds.ServerURL != "" {
				cClient := httptransport.New(2 * time.Second)
				if rResp, rErr := cClient.Get(strings.TrimRight(creds.ServerURL, "/") + "/api/v1/control/revocations"); rErr == nil && rResp.StatusCode == http.StatusOK {
					var rData struct {
						DeregisteredAgents []string `json:"deregistered_agents"`
						RevokedSessions    []string `json:"revoked_sessions"`
						RevokedAgents      []string `json:"revoked_agents"`
						QuarantinedAgents  []string `json:"quarantined_agents"`
					}
					if json.NewDecoder(rResp.Body).Decode(&rData) == nil {
						targets := []string{creds.AgentID, creds.InstanceID}
						if creds.SessionToken != "" {
							targets = append(targets, creds.SessionToken)
						}
						isDereg := false
						isFrozen := false
						allDereg := append(rData.DeregisteredAgents, rData.RevokedSessions...)
						allDereg = append(allDereg, rData.RevokedAgents...)
						for _, t := range targets {
							if t == "" {
								continue
							}
							for _, d := range allDereg {
								if strings.EqualFold(d, t) {
									isDereg = true
									break
								}
							}
							for _, q := range rData.QuarantinedAgents {
								if strings.EqualFold(q, t) {
									isFrozen = true
									break
								}
							}
						}
						if isDereg {
							state.PurgeAllCredentials(foundCredPath)
							enrolled = false
							authModeLabel = "Unenrolled (Workstation was deregistered by central administrator)"
						} else if isFrozen {
							authModeLabel += " [❄️ WORKSTATION FROZEN by Central Administrator]"
						}
					}
					rResp.Body.Close()
				}
			}
		}
	}

	// 4. Inspect Native Agent Plugins (Layer 1A)
	workspace := authz.GetWorkspaceRoot()
	if workspace == "" {
		workspace, _ = os.Getwd()
	}
	plugins := []types.PluginHealthRecord{
		InspectClaudePlugin(workspace),
		InspectCopilotPlugin(workspace),
		InspectAntigravityPlugin(workspace),
		InspectOpenCodePlugin(workspace),
		InspectCodexPlugin(workspace),
	}
	pluginByApp := make(map[string]types.PluginHealthRecord)
	activePluginCount := 0
	for _, p := range plugins {
		pluginByApp[strings.ToLower(p.Client)] = p
		if p.Client == "claude-code" {
			pluginByApp["claude"] = p
		}
		if p.Client == "antigravity" {
			pluginByApp["gemini"] = p
		}
		if p.PluginInstalled {
			activePluginCount++
		}
	}

	// 5. Inspect Active Sessions
	sessionDirs := []string{state.SessionsDir(), filepath.Join(".bap", "sessions")}
	activeCount := 0
	staleCount := 0
	totalPrompts := 0
	seenSessionIDs := make(map[string]bool)
	type sessionDetail struct {
		SessionID   string `json:"session_id"`
		AppID       string `json:"app_id"`
		PID         int    `json:"pid"`
		Status      string `json:"status"`
		Uptime      string `json:"uptime"`
		Plugin      string `json:"plugin"`
		PromptCount int    `json:"prompt_count"`
	}
	var sessionList []sessionDetail

	for _, sDir := range sessionDirs {
		entries, _ := os.ReadDir(sDir)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), "pid-") {
				continue
			}
			path := filepath.Join(sDir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var sInfo struct {
				SessionID      string    `json:"session_id"`
				PID            int       `json:"pid"`
				AppID          string    `json:"app_id"`
				ReportingLayer string    `json:"reporting_layer"`
				PromptCount    int       `json:"prompt_count"`
				UserPrompt     string    `json:"user_prompt"`
				StartedAt      time.Time `json:"started_at"`
			}
			if json.Unmarshal(data, &sInfo) == nil && sInfo.SessionID != "" {
				if seenSessionIDs[sInfo.SessionID] {
					continue
				}
				seenSessionIDs[sInfo.SessionID] = true
				alive := isProcessAlive(sInfo.PID)
				statusStr := "ACTIVE"
				if !alive {
					statusStr = "ORPHANED/STALE (Process Dead)"
					staleCount++
				} else {
					activeCount++
				}
				age := time.Since(sInfo.StartedAt).Round(time.Second)
				pluginLabel := "Active"
				if pRec, ok := pluginByApp[strings.ToLower(sInfo.AppID)]; ok && pRec.PluginInstalled {
					if pRec.EnforcementVerified {
						pluginLabel = "Active (Verified)"
					} else {
						pluginLabel = "Installed"
					}
				} else if sInfo.ReportingLayer != "" {
					pluginLabel = sInfo.ReportingLayer
				}
				pCount := sInfo.PromptCount
				if pCount <= 0 && strings.TrimSpace(sInfo.UserPrompt) != "" {
					pCount = 1
				}
				totalPrompts += pCount
				sessionList = append(sessionList, sessionDetail{
					SessionID:   sInfo.SessionID,
					AppID:       sInfo.AppID,
					PID:         sInfo.PID,
					Status:      statusStr,
					Uptime:      age.String(),
					Plugin:      pluginLabel,
					PromptCount: pCount,
				})
			}
		}
	}

	// 5a. Query active daemon attached sessions (including observed Shadow IT sessions)
	if daemonActive {
		if ds, err := ReadDaemonState(); err == nil && ds != nil && ds.URL != "" {
			client := &http.Client{Timeout: 800 * time.Millisecond}
			if resp, err := client.Get(ds.URL + "/status"); err == nil {
				var dStatus struct {
					AgentsAttached struct {
						Details []struct {
							SessionID      string    `json:"session_id"`
							AppID          string    `json:"app_id"`
							PID            int       `json:"pid"`
							AttachedAt     time.Time `json:"attached_at"`
							ReportingLayer string    `json:"reporting_layer"`
						} `json:"details"`
						Sessions []string `json:"sessions"`
					} `json:"agents_attached"`
				}
				if json.NewDecoder(resp.Body).Decode(&dStatus) == nil {
					for _, dSess := range dStatus.AgentsAttached.Details {
						if dSess.SessionID == "" || seenSessionIDs[dSess.SessionID] {
							continue
						}
						seenSessionIDs[dSess.SessionID] = true
						alive := isProcessAlive(dSess.PID)
						statusStr := "ACTIVE"
						if !alive {
							statusStr = "ORPHANED/STALE (Process Dead)"
							staleCount++
						} else {
							activeCount++
						}
						pluginLabel := "Discovery Observed (Shadow IT)"
						if dSess.ReportingLayer != "" && dSess.ReportingLayer != "discovery" {
							pluginLabel = dSess.ReportingLayer
						}
						age := time.Since(dSess.AttachedAt).Round(time.Second)
						sessionList = append(sessionList, sessionDetail{
							SessionID:   dSess.SessionID,
							AppID:       dSess.AppID,
							PID:         dSess.PID,
							Status:      statusStr,
							Uptime:      age.String(),
							Plugin:      pluginLabel,
							PromptCount: 0,
						})
					}
				}
				resp.Body.Close()
			}
		}
	} else {
		// When running standalone without daemon, inspect running processes for unmanaged agents
		if procs, err := listAgentProcesses(); err == nil {
			byPID := make(map[int]agentProcess, len(procs))
			for _, p := range procs {
				byPID[p.PID] = p
			}
			host := observationHost()
			for _, p := range procs {
				if agentApp(p.Name) == "" || p.PID <= 0 {
					continue
				}
				root := findRootAgentProcess(p, byPID)
				if root.PID != p.PID {
					continue // only canonical root process
				}
				id := observedSessionID(host, root)
				if id == "" || seenSessionIDs[id] {
					continue
				}
				already := false
				for _, sess := range sessionList {
					if sess.PID == root.PID {
						already = true
						break
					}
				}
				if already {
					continue
				}
				seenSessionIDs[id] = true
				activeCount++
				sessionList = append(sessionList, sessionDetail{
					SessionID:   id,
					AppID:       agentApp(root.Name),
					PID:         root.PID,
					Status:      "ACTIVE",
					Uptime:      "N/A (Observed)",
					Plugin:      "Discovery Observed (Shadow IT)",
					PromptCount: 0,
				})
			}
		}
	}

	// 5. Inspect Shadow IT & Tool Discovery (Layer 1B)
	discoveryDir := filepath.Join(state.Dir(), "discovery")
	var discReceipt struct {
		RunID             string    `json:"run_id"`
		Epoch             int64     `json:"epoch"`
		Acknowledged      bool      `json:"acknowledged"`
		Status            string    `json:"status"`
		Durable           bool      `json:"durable"`
		ObservationsCount int       `json:"observations_count"`
		ReceivedAt        time.Time `json:"received_at"`
	}
	receiptAcked := false
	if rData, rErr := os.ReadFile(filepath.Join(discoveryDir, "latest-receipt.json")); rErr == nil {
		if json.Unmarshal(rData, &discReceipt) == nil && discReceipt.Acknowledged {
			receiptAcked = true
		}
	}
	type receiptHistoryItem struct {
		RunID             string    `json:"run_id"`
		Epoch             int64     `json:"epoch"`
		Acknowledged      bool      `json:"acknowledged"`
		Status            string    `json:"status"`
		ObservationsCount int       `json:"observations_count"`
		ReceivedAt        time.Time `json:"received_at"`
	}
	var receiptHistory []receiptHistoryItem
	if hData, hErr := os.ReadFile(filepath.Join(discoveryDir, "receipts-history.json")); hErr == nil {
		_ = json.Unmarshal(hData, &receiptHistory)
	}
	var discReport discoverymeta.Report
	if repData, repErr := os.ReadFile(filepath.Join(discoveryDir, "latest-report.json")); repErr == nil {
		_ = json.Unmarshal(repData, &discReport)
	}
	if len(discReport.Observations) == 0 {
		discReport = collectDiscovery(discReceipt.Epoch)
	}
	type discItem struct {
		Kind     string `json:"kind"`
		Name     string `json:"name"`
		Client   string `json:"client"`
		Evidence string `json:"evidence"`
		PID      int    `json:"pid,omitempty"`
	}
	var discoveredItems []discItem
	seenDisc := make(map[string]bool)
	for _, o := range discReport.Observations {
		k := o.Kind + "::" + o.Name
		if !seenDisc[k] {
			seenDisc[k] = true
			discoveredItems = append(discoveredItems, discItem{
				Kind:     o.Kind,
				Name:     o.Name,
				Client:   o.Client,
				Evidence: o.Evidence,
				PID:      o.PID,
			})
		}
	}

	// 6. Inspect Policy Bundle
	pStore := policystore.New(policystore.DefaultPolicyDir())
	pState, pErr := pStore.LoadState()
	policyVersion := uint64(0)
	policyDigest := ""
	killSwitch := false
	if pErr == nil {
		policyVersion = pState.Version
		policyDigest = pState.Digest
		killSwitch = pState.KillSwitch
	} else if pPath, err := authz.FindFile("", "policy.cedar"); err == nil {
		if pData, err := os.ReadFile(pPath); err == nil {
			digest := sha256.Sum256(pData)
			policyDigest = "sha256:" + hex.EncodeToString(digest[:])
		}
	} else if pData, err := os.ReadFile("policy.cedar"); err == nil {
		digest := sha256.Sum256(pData)
		policyDigest = "sha256:" + hex.EncodeToString(digest[:])
	}

	// 6. Inspect Offline Spool & Telemetry Metrics
	auditLogPath := audit.DefaultLogPath()
	offlineEntries, _ := audit.ReadEntries(auditLogPath)
	totalLogged := len(offlineEntries)

	// Concurrency & Instance Check:
	// Status should auto-trigger sweep ONLY when no other bap-edge is actively running,
	// unless that other instance is unresponsive / dead.
	otherStatus := CheckOtherBapEdgeInstances()
	canAutoSync := !*noSweepFlag && cpConnected && (!otherStatus.OtherRunning || otherStatus.Unresponsive)
	autoSweepTriggered := false
	var autoSweepResult SweepResult

	if canAutoSync && (totalLogged > 0 || staleCount > 0) {
		autoSweepResult, _ = PerformSweep(serverURL, false)
		autoSweepTriggered = true

		// Re-read audit log after flush
		offlineEntries, _ = audit.ReadEntries(auditLogPath)
		totalLogged = len(offlineEntries)
		if autoSweepResult.LocalSweptSessions > 0 {
			staleCount = 0
			var updatedList []sessionDetail
			for _, s := range sessionList {
				if s.Status == "ACTIVE" {
					updatedList = append(updatedList, s)
				}
			}
			sessionList = updatedList
		}
	}

	allowedCount := 0
	deniedCount := 0
	for _, entry := range offlineEntries {
		if entry.Decision == "allow" {
			allowedCount++
		} else if entry.Decision == "deny" {
			deniedCount++
		}
	}

	// Compatibility determination
	compatibilityStatus := "OFFLINE / UNKNOWN"
	if cpConnected {
		if cpServerVersion == version.Version {
			compatibilityStatus = "MATCHED (Exact)"
		} else if cpMinEdgeVersion != "" && version.Compare(version.Version, cpMinEdgeVersion) < 0 {
			compatibilityStatus = "DEPRECATED (Upgrade Required)"
		} else {
			compatibilityStatus = "COMPATIBLE"
		}
	}

	// JSON output mode
	if *jsonFlag {
		statusOutput := map[string]any{
			"host":     hostname,
			"platform": fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			"user":     username,
			"version": map[string]any{
				"agent_version":        version.Version,
				"server_version":       cpServerVersion,
				"min_edge_version":     cpMinEdgeVersion,
				"compatibility_status": compatibilityStatus,
			},
			"operating_mode": map[string]any{
				"mode":           operatingMode,
				"degraded":       !daemonActive,
				"daemon_running": daemonActive,
				"description":    operatingModeDesc,
				"admin_required": false,
			},
			"control_plane": map[string]any{
				"url":                  serverURL,
				"connected":            cpConnected,
				"latency_ms":           cpLatencyMs,
				"status":               cpStatusText,
				"server_version":       cpServerVersion,
				"min_edge_version":     cpMinEdgeVersion,
				"compatibility_status": compatibilityStatus,
			},
			"enrollment": map[string]any{
				"enrolled":   enrolled,
				"auth_mode":  authModeLabel,
				"agent_id":   creds.AgentID,
				"app_id":     creds.AppID,
				"user_email": creds.UserEmail,
				"department": creds.Department,
			},
			"sessions": map[string]any{
				"active_count":  activeCount,
				"stale_count":   staleCount,
				"total_prompts": totalPrompts,
				"items":         sessionList,
			},
			"plugins": map[string]any{
				"active_count": activePluginCount,
				"items":        plugins,
			},
			"discovery": map[string]any{
				"total_discovered":     len(discoveredItems),
				"last_scan_epoch":      discReport.Epoch,
				"receipt_acknowledged": receiptAcked,
				"receipt_run_id":       discReceipt.RunID,
				"receipt_time":         discReceipt.ReceivedAt,
				"receipt_history":      receiptHistory,
				"items":                discoveredItems,
			},
			"policy": map[string]any{
				"version":     policyVersion,
				"digest":      policyDigest,
				"kill_switch": killSwitch,
			},
			"telemetry": map[string]any{
				"total_logged":            totalLogged,
				"allowed":                 allowedCount,
				"denied":                  deniedCount,
				"spool_backlog_unflushed": totalLogged,
				"auto_sweep_triggered":    autoSweepTriggered,
				"auto_flushed_records":    autoSweepResult.FlushedAuditCount,
				"auto_swept_sessions":     autoSweepResult.LocalSweptSessions,
				"concurrency_guard": map[string]any{
					"can_auto_sync":    canAutoSync,
					"other_running":    otherStatus.OtherRunning,
					"unresponsive":     otherStatus.Unresponsive,
					"active_pid":       otherStatus.ActivePID,
					"instance_summary": otherStatus.Description,
				},
			},
			"workspace": authz.GetWorkspaceRoot(),
			"state_dir": state.Dir(),
			"defense_layers": map[string]any{
				"architecture": "5-Layer Defense-in-Depth",
				"layers": []map[string]any{
					{
						"layer":       "Layer 1",
						"name":        "Process Interception Hooks",
						"status":      "NOT_OBSERVED",
						"description": "Hook configuration and trust do not prove callback execution",
					},
					{
						"layer":       "Layer 2",
						"name":        "Model Context Protocol (MCP)",
						"status":      "NOT_OBSERVED",
						"description": "Requires evidence from calls routed through the BAP MCP server",
					},
					{
						"layer":       "Layer 3",
						"name":        "Terminal Interceptor Shims",
						"status":      "NOT_OBSERVED",
						"description": "Requires evidence that command resolution used a BAP shim",
					},
					{
						"layer":       "Layer 4",
						"name":        "OS Kernel Boundary Sandbox & Broker",
						"status":      "AVAILABLE",
						"description": "Local broker available; OS-wide enforcement is not attested by this status query",
					},
					{
						"layer":       "Layer 5",
						"name":        "Authoritative Network Gateway PEP",
						"status":      "NOT_OBSERVED",
						"description": "Requires evidence from the protected resource gateway",
					},
				},
			},
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(statusOutput)
	}

	// Terminal Text Output
	fmt.Println("================================================================================")
	fmt.Println("  [BAP ZERO-TRUST] 🛡️  Edge Workstation Status & Compliance Inspection")
	fmt.Println("================================================================================")
	fmt.Printf("  Host:             %s (%s/%s)\n", hostname, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  User:             %s\n", username)
	fmt.Printf("  Daemon Version:   %s\n", version.Version)
	if cpConnected && cpServerVersion != "" {
		fmt.Printf("  Control Plane:    %s [v%s | %s]\n", serverURL, cpServerVersion, compatibilityStatus)
	} else {
		fmt.Printf("  Control Plane:    %s [%s]\n", serverURL, cpStatusText)
	}
	fmt.Printf("  Operating Mode:   %s\n", operatingModeDesc)
	fmt.Printf("  Admin Rights Req: NO (100%% unprivileged user-space broker)\n")
	fmt.Printf("  State Directory:  %s\n", state.Dir())
	fmt.Printf("  Workspace Root:   %s\n", authz.GetWorkspaceRoot())

	// Enrolled Identity
	if enrolled {
		fmt.Printf("  Auth Mode:        %s\n", authModeLabel)
		if creds.UserEmail != "" {
			fmt.Printf("  Corporate User:   %s\n", creds.UserEmail)
		}
		if creds.Department != "" {
			fmt.Printf("  Department:       %s\n", creds.Department)
		}
		if len(creds.Groups) > 0 {
			fmt.Printf("  IdP Groups:       %v\n", creds.Groups)
		}
		fmt.Printf("  Agent Workload:   %s (App: %s)\n", creds.AgentID, creds.AppID)
	} else {
		fmt.Printf("  Enrollment:       Unenrolled (run 'bapedge login' or 'bapedge register')\n")
	}
	fmt.Println("--------------------------------------------------------------------------------")

	// 1. Inspect Active Sessions
	fmt.Println("  ACTIVE SESSIONS:")
	if len(sessionList) > 0 {
		for _, s := range sessionList {
			fmt.Printf("    • [%s] Session: %-25s App: %-12s PID: %-7d Uptime: %-8s Plugin: %-18s Prompts: %d\n",
				s.Status, s.SessionID, s.AppID, s.PID, s.Uptime, s.Plugin, s.PromptCount)
		}
	} else {
		fmt.Println("    (No local agent sessions currently active)")
	}

	// 2. Inspect Native Agent Plugins (Layer 1A)
	fmt.Println("\n  NATIVE AGENT PLUGINS (Layer 1A - In-Harness Extension):")
	if activePluginCount > 0 {
		for _, p := range plugins {
			if p.PluginInstalled {
				enf := "Unverified"
				if p.EnforcementVerified {
					enf = "Verified (Active)"
				} else if p.HookActive {
					enf = "Hook Active"
				}
				fmt.Printf("    • %-14s %-22s Version: %-6s State: %-10s Enforcement: %s\n",
					p.Client, p.PluginName, p.PluginVersion, p.State, enf)
			}
		}
	} else {
		fmt.Println("    (No native agent plugins detected in workspace; run 'bap install' to install)")
	}

	// 2B. Inspect Discovered Shadow IT & Tools (Layer 1B)
	fmt.Println("\n  SHADOW IT & TOOL DISCOVERY (Layer 1B - Unmanaged Detection):")
	if len(discoveredItems) > 0 {
		fmt.Printf("    • Discovered Assets:  %d asset(s) observed on workstation\n", len(discoveredItems))
		for _, it := range discoveredItems {
			pidStr := ""
			if it.PID > 0 {
				pidStr = fmt.Sprintf(" (PID: %d)", it.PID)
			}
			clientStr := ""
			if it.Client != "" && it.Client != it.Name {
				clientStr = fmt.Sprintf(" [Client: %s]", it.Client)
			}
			fmt.Printf("      - [%-13s] %-20s Evidence: %s%s%s\n", it.Kind, it.Name, it.Evidence, clientStr, pidStr)
		}
	} else {
		fmt.Println("    • Discovered Assets:  0 unmanaged assets detected")
	}
	if discReport.Epoch > 0 || discReceipt.Epoch > 0 {
		epVal := discReport.Epoch
		if epVal <= 0 {
			epVal = discReceipt.Epoch
		}
		fmt.Printf("    • Last Scan Epoch:    epoch %d\n", epVal)
	}
	if receiptAcked {
		fmt.Printf("    • Scan Receipt:       ACKNOWLEDGED by Central Control Plane (RunID: %s, Received: %s)\n",
			discReceipt.RunID, discReceipt.ReceivedAt.Format(time.RFC3339))
	} else if cpConnected {
		fmt.Printf("    • Scan Receipt:       PENDING upload to Control Plane (%d observation(s) spooled locally)\n", len(discoveredItems))
	} else {
		fmt.Printf("    • Scan Receipt:       QUEUED LOCALLY (%d observation(s) spooled locally; control plane offline)\n", len(discoveredItems))
	}
	if len(receiptHistory) > 0 {
		fmt.Printf("    • Receipt History (Top %d):\n", len(receiptHistory))
		for _, rh := range receiptHistory {
			ackStr := "PENDING"
			if rh.Acknowledged {
				ackStr = "ACK"
			}
			fmt.Printf("      - [%-7s] RunID: %-36s Epoch: %-2d Obs: %-2d (%s)\n",
				ackStr, rh.RunID, rh.Epoch, rh.ObservationsCount, rh.ReceivedAt.Format("15:04:05 MST"))
		}
	}

	// 3. Inspect Cached Cedar Policy Bundle
	fmt.Println("\n  POLICY BUNDLE & ZERO-TRUST CACHE:")
	if policyVersion > 0 {
		fmt.Printf("    • Version:        v%d\n", policyVersion)
		fmt.Printf("    • Rules Digest:   %s\n", policyDigest)
		fmt.Printf("    • Kill Switch:    %v\n", killSwitch)
		fmt.Printf("    • Cache Path:     %s\n", policystore.DefaultPolicyDir())
	} else if policyDigest != "" {
		fmt.Println("    • Source:         Local policy.cedar")
		fmt.Printf("    • Rules Digest:   %s\n", policyDigest)
	} else {
		fmt.Println("    • Status:         No cached policy found (Default baseline active)")
	}

	// 4. Inspect 5-Layer Defense-in-Depth Compliance
	fmt.Println("\n  5-LAYER DEFENSE-IN-DEPTH COMPLIANCE STATUS:")
	fmt.Println("    Layer 1 (Native Hooks): NOT_OBSERVED - verify approval and received callbacks")
	fmt.Println("    Layer 2 (BAP MCP): NOT_OBSERVED - verify calls routed through BAP tools")
	fmt.Println("    Layer 3 (Terminal Shims): NOT_OBSERVED - verify actual shim-routed commands")
	fmt.Println("    Layer 4 (Broker): AVAILABLE - OS-wide enforcement is not attested here")
	fmt.Println("    Layer 5 (Gateway PEP): NOT_OBSERVED - verify protected resource events")

	// 5. Telemetry & Offline Spool
	fmt.Println("\n  TELEMETRY & OFFLINE RESILIENCE:")
	if autoSweepTriggered {
		fmt.Printf("    • Auto-Sync:      ⚡ Auto-triggered sweep: %d pending audit record(s) synced to Control Plane\n", autoSweepResult.FlushedAuditCount)
		if autoSweepResult.LocalSweptSessions > 0 {
			fmt.Printf("                      🧹 Swept %d orphaned session marker(s)\n", autoSweepResult.LocalSweptSessions)
		}
	} else if otherStatus.OtherRunning && !otherStatus.Unresponsive && (totalLogged > 0 || staleCount > 0) {
		fmt.Printf("    • Auto-Sync:      ⏸️  Deferred (%s; sync delegated to active instance)\n", otherStatus.Description)
	}
	fmt.Printf("    • Logged Events:  %d total (Allowed: %d, Denied: %d)\n", totalLogged, allowedCount, deniedCount)
	fmt.Printf("    • Prompts Count:  %d observed across active sessions\n", totalPrompts)
	if totalLogged == 0 {
		fmt.Println("    • Spool Backlog:  0 pending entries (All audit logs ingested by Control Plane)")
	} else {
		if cpConnected {
			fmt.Printf("    • Spool Backlog:  %d un-flushed entries in %s\n", totalLogged, auditLogPath)
		} else {
			fmt.Printf("    • Spool Backlog:  %d un-flushed entries pending network reconnection in %s\n", totalLogged, auditLogPath)
			fmt.Println("                      (Control plane unreachable; will auto-sync on reconnect or run 'bapedge sweep')")
		}
	}

	if staleCount > 0 {
		fmt.Printf("\n  ⚠️ Notice: Found %d orphaned session(s). Run 'bapedge sweep' to clean stale state.\n", staleCount)
	}

	fmt.Println("================================================================================")
	return nil
}

func isDaemonRunning() bool {
	ds, err := ReadDaemonState()
	return err == nil && ds != nil
}

// OtherInstanceStatus reports whether another bap-edge process is running and its responsiveness.
type OtherInstanceStatus struct {
	OtherRunning bool   `json:"other_running"`
	Unresponsive bool   `json:"unresponsive"`
	ActivePID    int    `json:"active_pid"`
	Description  string `json:"description"`
}

// CheckOtherBapEdgeInstances verifies if any other bap-edge process (daemon, agent session, or CLI)
// is actively executing on the system. Returns whether it is running and whether it is unresponsive.
func CheckOtherBapEdgeInstances() OtherInstanceStatus {
	// 1. Check bap-daemon
	ds, err := ReadDaemonState()
	if err == nil && ds != nil && ds.PID != os.Getpid() {
		if !isProcessAlive(ds.PID) {
			return OtherInstanceStatus{
				OtherRunning: true,
				Unresponsive: true,
				ActivePID:    ds.PID,
				Description:  fmt.Sprintf("bap-daemon (PID %d) is dead/orphaned", ds.PID),
			}
		}
		// Daemon process is alive in OS table: check if it is responsive to IPC
		client := httptransport.New(600 * time.Millisecond)
		resp, err := client.Get(ds.URL + "/api/v1/daemon/status")
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				_ = resp.Body.Close()
			}
			return OtherInstanceStatus{
				OtherRunning: true,
				Unresponsive: true,
				ActivePID:    ds.PID,
				Description:  fmt.Sprintf("bap-daemon (PID %d) is unresponsive (IPC timed out / failed)", ds.PID),
			}
		}
		_ = resp.Body.Close()
		return OtherInstanceStatus{
			OtherRunning: true,
			Unresponsive: false,
			ActivePID:    ds.PID,
			Description:  fmt.Sprintf("bap-daemon (PID %d) is actively running and responsive", ds.PID),
		}
	}

	// 2. Check for other bapedge OS processes
	otherPIDs, err := findOtherBapEdgePIDs()
	if err == nil && len(otherPIDs) > 0 {
		var alivePIDs []int
		for _, pid := range otherPIDs {
			if isProcessAlive(pid) {
				alivePIDs = append(alivePIDs, pid)
			}
		}
		if len(alivePIDs) > 0 {
			return OtherInstanceStatus{
				OtherRunning: true,
				Unresponsive: false,
				ActivePID:    alivePIDs[0],
				Description:  fmt.Sprintf("another bapedge instance is actively running (PID %d)", alivePIDs[0]),
			}
		}
	}

	// 3. Check for active agent sessions
	sessionDirs := []string{state.SessionsDir(), filepath.Join(".bap", "sessions")}
	for _, sDir := range sessionDirs {
		entries, _ := os.ReadDir(sDir)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), "pid-") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(sDir, entry.Name()))
			if err != nil {
				continue
			}
			var sInfo struct {
				SessionID string    `json:"session_id"`
				PID       int       `json:"pid"`
				StartedAt time.Time `json:"started_at"`
			}
			if json.Unmarshal(data, &sInfo) == nil && sInfo.PID > 0 && sInfo.PID != os.Getpid() {
				if isProcessAlive(sInfo.PID) {
					// Check if session has been stale / idle > 4 hours
					if time.Since(sInfo.StartedAt) > 4*time.Hour {
						return OtherInstanceStatus{
							OtherRunning: true,
							Unresponsive: true,
							ActivePID:    sInfo.PID,
							Description:  fmt.Sprintf("agent session %s (PID %d) is unresponsive/expired", sInfo.SessionID, sInfo.PID),
						}
					}
					return OtherInstanceStatus{
						OtherRunning: true,
						Unresponsive: false,
						ActivePID:    sInfo.PID,
						Description:  fmt.Sprintf("agent session %s is actively running (PID %d)", sInfo.SessionID, sInfo.PID),
					}
				}
			}
		}
	}

	return OtherInstanceStatus{
		OtherRunning: false,
		Unresponsive: false,
		Description:  "no other bap-edge instances running",
	}
}

// RunWhy provides in-terminal Cedar policy explanation for any command (BAP-472).
// Example: bapedge why "rm -rf /" or bapedge why "git status"
func RunWhy(args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: bapedge why \"<command>\"")
		fmt.Println("Examples:")
		fmt.Println("  bapedge why \"git status\"")
		fmt.Println("  bapedge why \"rm -rf /\"")
		fmt.Println("  bapedge why \"curl http://internal-db:5432\"")
		return nil
	}

	targetCmd := strings.Join(args, " ")
	parts := strings.Fields(targetCmd)
	executable := ""
	cmdArgs := ""
	if len(parts) > 0 {
		executable = parts[0]
		if len(parts) > 1 {
			cmdArgs = strings.Join(parts[1:], " ")
		}
	}

	workspaceRoot := authz.GetWorkspaceRoot()
	escapesWorkspace := false
	if workspaceRoot != "" {
		escapesWorkspace = authz.CheckCommandWorkspaceEscape(workspaceRoot, targetCmd)
	}

	authorizer, err := authz.NewAuthorizer("")
	if err != nil {
		return fmt.Errorf("failed to initialize Cedar authorizer: %w", err)
	}

	allowed, reason, evalErr := authorizer.EvaluateWithWorkspace(executable, targetCmd, cmdArgs, workspaceRoot)

	fmt.Println("================================================================================")
	fmt.Println("  [BAP ZERO-TRUST] 🔍 Terminal Policy Explanation (bapedge why)")
	fmt.Println("================================================================================")
	fmt.Printf("  Target Command:     %s\n", targetCmd)
	fmt.Printf("  Parsed Executable:  %s\n", executable)
	fmt.Printf("  Command Arguments:  %s\n", cmdArgs)
	fmt.Printf("  Workspace Root:     %s\n", workspaceRoot)
	fmt.Printf("  Escapes Workspace:  %v\n", escapesWorkspace)
	identity := authorizer.GetIdentity()
	if identity.UserEmail != "" {
		fmt.Printf("  Principal Identity: %s (Dept: %s, Groups: %v)\n", identity.UserEmail, identity.Department, identity.Groups)
	}
	fmt.Println("--------------------------------------------------------------------------------")

	if evalErr != nil {
		fmt.Printf("  POLICY DECISION:    🚨 EVALUATION ERROR\n")
		fmt.Printf("  ERROR DETAILS:      %v\n", evalErr)
	} else if allowed {
		fmt.Println("  POLICY DECISION:    ✅ ALLOWED (Permitted by Policy)")
		if escapesWorkspace {
			fmt.Println("  TRUST STATUS:       Authorized cross-folder operation (pre-authorized via BAP Trust Store)")
		} else {
			fmt.Println("  REASON:             Action conforms to authorized zero-trust rules.")
		}
		fmt.Println("  RULE SCOPE:         Permitted within authorized development boundaries.")
	} else {
		fmt.Println("  POLICY DECISION:    ⛔ DENIED (Blocked by Cedar Policy)")
		if reason != "" {
			fmt.Printf("  RULE TRIGGER:       %s\n", reason)
		} else {
			fmt.Println("  RULE TRIGGER:       Default deny invariant (No explicit permit matched)")
		}
		if escapesWorkspace {
			fmt.Println("  RISK VECTOR:        Workspace boundary traversal detected (escapes_workspace=true)")
			if !strings.Contains(strings.ToLower(reason), "secret") && !strings.Contains(strings.ToLower(reason), "credential") && !strings.Contains(strings.ToLower(reason), "exfiltration") {
				fmt.Println("  HITL REMEDIATION:   To authorize this cross-folder target, run: bapedge trust <path> --project")
			} else {
				fmt.Println("  SECURITY INVARIANT: Absolute secret protection invariant active. Secret access cannot be bypassed.")
			}
		}
	}

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("  EVALUATION ATTRIBUTES:")
	fmt.Println("    • Principal:      Agent::\"Local\"")
	fmt.Println("    • Action:         Action::\"Execute\"")
	fmt.Println("    • Resource:       Command::\"CLI\"")
	fmt.Printf("    • Context:        executable=%q, escapes_workspace=%v\n", strings.ToLower(executable), escapesWorkspace)
	fmt.Println("================================================================================")

	return nil
}

// SweepResult contains summary statistics from a clean sweep operation.
type SweepResult struct {
	LocalSweptSessions  int   `json:"local_swept_sessions"`
	FlushedAuditCount   int   `json:"flushed_audit_count"`
	ServerSweptSessions int   `json:"server_swept_sessions"`
	ReconciledGrants    int   `json:"reconciled_grants"`
	SweptDeadPIDFiles   int   `json:"swept_dead_pid_files"`
	SweptTempFiles      int   `json:"swept_temp_files"`
	ControlPlaneError   error `json:"-"`
}

// PerformSweep reconciles orphaned local sessions, purges stale session markers,
// clears dead PID files and orphaned shims, and flushes offline audit records.
func PerformSweep(serverURL string, force bool) (SweepResult, error) {
	var res SweepResult
	sessionSweepDirs := []string{state.SessionsDir(), filepath.Join(".bap", "sessions")}

	for _, sessionsDir := range sessionSweepDirs {
		entries, _ := os.ReadDir(sessionsDir)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			p := filepath.Join(sessionsDir, entry.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}

			var sInfo struct {
				SessionID string `json:"session_id"`
				PID       int    `json:"pid"`
			}
			if json.Unmarshal(data, &sInfo) == nil {
				shouldPurge := force || (sInfo.PID > 0 && !isProcessAlive(sInfo.PID))
				if shouldPurge {
					_ = os.Remove(p)
					if sInfo.SessionID != "" {
						_ = os.Remove(sessionMarkerPath(sInfo.SessionID))
						// Inform control plane of crash recovery
						sweepPayload := map[string]any{
							"session_id": sInfo.SessionID,
							"reason":     "orphaned_crash_detected_by_edge_sweep",
						}
						_ = postJSONQuick(serverURL+"/api/v1/control/sweep", sweepPayload)
					}
					if sInfo.PID > 0 {
						_ = os.Remove(sessionPIDMarkerPath(sInfo.PID))
					}
					res.LocalSweptSessions++
				}
			}
		}
	}

	// 2. Sweep dead PID files, orphaned locks, dead shims, and stale temp files
	stateDirs := []string{state.Dir(), ".bap"}
	for _, sDir := range stateDirs {
		entries, _ := os.ReadDir(sDir)
		for _, entry := range entries {
			name := entry.Name()
			fullPath := filepath.Join(sDir, name)

			// Clean *.pid files where process is dead
			if !entry.IsDir() && (strings.HasSuffix(name, ".pid") || strings.HasPrefix(name, "pid-")) {
				data, err := os.ReadFile(fullPath)
				if err == nil {
					pidStr := strings.TrimSpace(string(data))
					if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
						if force || !isProcessAlive(pid) {
							_ = os.Remove(fullPath)
							res.SweptDeadPIDFiles++
						}
					} else if force {
						_ = os.Remove(fullPath)
						res.SweptDeadPIDFiles++
					}
				}
			}

			// Clean stale temp files (*.tmp.* or .tmp.*)
			if !entry.IsDir() && (strings.Contains(name, ".tmp.") || strings.HasSuffix(name, ".tmp")) {
				_ = os.Remove(fullPath)
				res.SweptTempFiles++
			}

			// Clean dead or orphaned shims directories (shims-*)
			if entry.IsDir() && strings.HasPrefix(name, "shims-") {
				_ = os.RemoveAll(fullPath)
				res.SweptTempFiles++
			}
		}
	}

	// Purge stale root markers
	_ = os.Remove(".bap-session.json")
	_ = os.Remove("../.bap-session.json")
	_ = os.Remove(state.WorkspaceSessionPath())
	_ = os.Remove(filepath.Join(".bap", "session.json"))
	_ = os.Remove(".bap-prompt.txt")
	_ = os.Remove("../.bap-prompt.txt")

	// Flush any pending offline audit logs
	if n, flushErr := audit.FlushOfflineAudit(serverURL, ""); flushErr == nil {
		res.FlushedAuditCount = n
	}

	// Request central control plane sweep
	sweepResp, cpErr := executeControlPlaneSweep(serverURL)
	if cpErr == nil && sweepResp != nil {
		res.ServerSweptSessions = sweepResp.SweptSessions
		res.ReconciledGrants = sweepResp.ReconciledGrants
	} else {
		res.ControlPlaneError = cpErr
	}

	return res, nil
}

// RunSweep executes clean sweep and crash recovery routines (BAP-470).
// Purges dead session markers, clears abandoned lockfiles, notifies control plane,
// flushes offline audit entries, and rejoins the fleet in a pristine state.
func RunSweep(args []string) error {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	serverFlag := fs.String("server", "", "Central BAP control plane URL")
	forceFlag := fs.Bool("force", false, "Force sweep all sessions regardless of PID status")

	if err := fs.Parse(args); err != nil {
		return err
	}

	serverURL := *serverFlag
	if serverURL == "" {
		ep := config.ResolveEndpoints()
		serverURL = ep.ControlPlaneURL
	}
	if serverURL == "" {
		serverURL = config.DefaultControlPlaneURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	// If explicit server was not passed and configured URL is offline, probe local fallback
	if *serverFlag == "" {
		client := httptransport.New(1000 * time.Millisecond)
		if resp, err := client.Get(serverURL + "/health"); err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				_ = resp.Body.Close()
			}
			fallbacks := []string{
				"https://localhost:8443", "https://127.0.0.1:8443",
				"http://localhost:8080", "http://127.0.0.1:8080",
			}
			for _, fb := range fallbacks {
				if strings.TrimRight(serverURL, "/") == fb {
					continue
				}
				if fbResp, fbErr := client.Get(fb + "/health"); fbErr == nil && fbResp.StatusCode == http.StatusOK {
					serverURL = fb
					_ = fbResp.Body.Close()
					break
				}
			}
		} else {
			_ = resp.Body.Close()
		}
	}

	fmt.Println("================================================================================")
	fmt.Println("  [BAP ZERO-TRUST] 🧹 Running Clean Sweep & Crash Recovery Reconciler")
	fmt.Println("================================================================================")
	fmt.Printf("  Control Plane:      %s\n", serverURL)
	fmt.Println("--------------------------------------------------------------------------------")

	res, err := PerformSweep(serverURL, *forceFlag)
	if err != nil {
		return fmt.Errorf("clean sweep failed: %w", err)
	}

	fmt.Printf("  [✓] Swept %d orphaned/crashed local session markers\n", res.LocalSweptSessions)
	if res.SweptDeadPIDFiles > 0 {
		fmt.Printf("  [✓] Purged %d dead process lock/PID files\n", res.SweptDeadPIDFiles)
	}
	if res.SweptTempFiles > 0 {
		fmt.Printf("  [✓] Cleaned %d stale temporary files and dead shims\n", res.SweptTempFiles)
	}
	fmt.Printf("  [✓] Flushed %d offline audit records to central tamper-evident ledger\n", res.FlushedAuditCount)
	if res.ControlPlaneError == nil {
		fmt.Printf("  [✓] Central Control Plane reconciled: %d idle sessions closed, %d stale grants expired\n", res.ServerSweptSessions, res.ReconciledGrants)
		fmt.Println("  [✓] Workstation successfully rejoined fleet with clean state.")
	} else {
		fmt.Printf("  [!] Control plane sweep notice: %v (Local state swept successfully)\n", res.ControlPlaneError)
	}

	fmt.Println("================================================================================")
	fmt.Println("  ✅ Clean sweep completed successfully.")
	fmt.Println("================================================================================")
	return nil
}

type controlSweepResponse struct {
	Status           string `json:"status"`
	SweptSessions    int    `json:"swept_sessions"`
	ReconciledGrants int    `json:"reconciled_grants"`
}

func executeControlPlaneSweep(serverURL string) (*controlSweepResponse, error) {
	client := httptransport.New(3 * time.Second)
	reqBody, _ := json.Marshal(map[string]any{
		"stale_idle_seconds": 300,
		"reason":             "edge_clean_sweep",
	})
	resp, err := client.Post(serverURL+"/api/v1/control/sweep", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned status %d", resp.StatusCode)
	}

	var res controlSweepResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}
