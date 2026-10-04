package cmd

import (
	"bap-edge/internal/httptransport"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"bap-edge/internal/config"
)

var isLocalScanRunning atomic.Bool


// RunSessionStart executes a zero-trust pre-flight check and starts the session.
// If the user or session is revoked, prints an alert and exits with code 2.
// If authorized, persists .bap-session.json and spawns the background watcher.
func RunSessionStart(args []string) error {
	fs := flag.NewFlagSet("session-start", flag.ContinueOnError)
	serverFlag := fs.String("server", "", "Central control plane URL")
	sessionFlag := fs.String("session-id", "", "Session ID to watch and govern")
	appFlag := fs.String("app-id", "claude-code", "Governed workload identifier")
	pidFlag := fs.Int("pid", 0, "Target process ID to watch (default: parent PID)")
	promptFlag := fs.String("prompt", "", "Initial user prompt")

	if err := fs.Parse(args); err != nil {
		return err
	}

	watchPID := *pidFlag
	if watchPID <= 0 {
		watchPID = os.Getppid()
	}

	serverURL := *serverFlag
	if serverURL == "" {
		ep := config.ResolveEndpoints()
		serverURL = ep.ControlPlaneURL
	}
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	sessionID := *sessionFlag
	if sessionID == "" {
		sessionID = os.Getenv("BAP_SESSION_ID")
	}
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-%s-%d", *appFlag, watchPID)
	}

	// Purge dead session markers from previous crashed/killed sessions
	cleanupStaleSessionMarkers()

	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	hostname, _ := os.Hostname()

	initialPrompt := *promptFlag
	if initialPrompt == "" {
		initialPrompt = strings.TrimSpace(os.Getenv("BAP_USER_PROMPT"))
	}

	// 1. Check local .bap-revoked file
	for _, cand := range []string{".bap-revoked", "../.bap-revoked"} {
		if data, err := os.ReadFile(cand); err == nil {
			var info struct {
				UserID string `json:"user_id"`
				Reason string `json:"reason"`
			}
			if json.Unmarshal(data, &info) == nil {
				if info.UserID == "" || strings.EqualFold(info.UserID, username) {
					reason := info.Reason
					if reason == "" {
						reason = "User access has been revoked by administrator"
					}
					fmt.Fprintf(os.Stderr, "\n===============================================================================\n")
					fmt.Fprintf(os.Stderr, "  [BAP ZERO-TRUST] 🚨 SESSION STARTUP BLOCKED\n")
					fmt.Fprintf(os.Stderr, "  User '%s' access has been REVOKED by administrator.\n", username)
					fmt.Fprintf(os.Stderr, "  Reason: %s\n", reason)
					fmt.Fprintf(os.Stderr, "  All new Claude Code sessions are denied until access is restored.\n")
					fmt.Fprintf(os.Stderr, "===============================================================================\n\n")
					os.Exit(2)
				}
			}
		}
	}

	// 2. Pre-flight check with Central Control Plane
	startPayload := map[string]any{
		"session_id":  sessionID,
		"app_id":      *appFlag,
		"user_id":     username,
		"hostname":    hostname,
		"client_pid":  watchPID,
		"user_prompt": initialPrompt,
	}
	body, _ := json.Marshal(startPayload)
	client := httptransport.New(3 * time.Second)
	resp, err := client.Post(serverURL+"/api/v1/sessions/start", "application/json", bytes.NewReader(body))
	if err == nil && resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			var errResp struct {
				Error string `json:"error"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			reason := errResp.Error
			if reason == "" {
				reason = "User access has been revoked by administrator"
			}
			writeLocalRevoked(sessionID, reason)
			fmt.Fprintf(os.Stderr, "\n===============================================================================\n")
			fmt.Fprintf(os.Stderr, "  [BAP ZERO-TRUST] 🚨 SESSION STARTUP BLOCKED\n")
			fmt.Fprintf(os.Stderr, "  User '%s' access has been REVOKED by administrator.\n", username)
			fmt.Fprintf(os.Stderr, "  Reason: %s\n", reason)
			fmt.Fprintf(os.Stderr, "  All new Claude Code sessions are denied until access is restored.\n")
			fmt.Fprintf(os.Stderr, "===============================================================================\n\n")
			os.Exit(2)
		}
	}

	// 3. Persist workspace session marker with PID
	writeSessionMarker(sessionID, serverURL, *appFlag, username, hostname, initialPrompt, watchPID)

	// 4. Start continuous background heartbeat watcher
	exe, err := os.Executable()
	if err != nil {
		exe = "bapedge.exe"
	}
	cmdArgs := []string{
		"watch",
		fmt.Sprintf("--pid=%d", watchPID),
		fmt.Sprintf("--server=%s", serverURL),
		fmt.Sprintf("--session-id=%s", sessionID),
		fmt.Sprintf("--app-id=%s", *appFlag),
	}
	detachedCmd := exec.Command(exe, cmdArgs...)
	detachedCmd.SysProcAttr = getSysProcAttrDetached()
	_ = detachedCmd.Start()

	return nil
}

// RunSessionEnd gracefully closes a session on the control plane and removes local session markers.
func RunSessionEnd(args []string) error {
	fs := flag.NewFlagSet("session-end", flag.ContinueOnError)
	serverFlag := fs.String("server", "", "Central control plane URL")
	sessionFlag := fs.String("session-id", "", "Session ID to end")
	reasonFlag := fs.String("reason", "Claude Code closed gracefully", "Exit reason")

	if err := fs.Parse(args); err != nil {
		return err
	}

	serverURL := *serverFlag
	if serverURL == "" {
		ep := config.ResolveEndpoints()
		serverURL = ep.ControlPlaneURL
	}
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	sessionID := *sessionFlag
	if sessionID == "" {
		sessionID = os.Getenv("BAP_SESSION_ID")
	}
	if sessionID == "" {
		for _, loc := range []string{".bap-session.json", "../.bap-session.json"} {
			if data, err := os.ReadFile(loc); err == nil {
				var sInfo struct {
					SessionID string `json:"session_id"`
				}
				if json.Unmarshal(data, &sInfo) == nil && sInfo.SessionID != "" {
					sessionID = sInfo.SessionID
					break
				}
			}
		}
	}

	if sessionID != "" {
		endPayload := map[string]any{
			"session_id": sessionID,
			"reason":     *reasonFlag,
		}
		_ = postJSONQuick(serverURL+"/api/v1/sessions/end", endPayload)
	}

	cleanupSessionMarker(sessionID, 0)
	_ = os.Remove(".bap-prompt.txt")
	_ = os.Remove("../.bap-prompt.txt")
	return nil
}

// RunWatch starts a process watcher thread / background monitor for an agent session.
func RunWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	pidFlag := fs.Int("pid", 0, "Target process ID to watch (default: parent PID)")
	serverFlag := fs.String("server", "", "Central control plane URL")
	sessionFlag := fs.String("session-id", "", "Session ID to watch and govern")
	appFlag := fs.String("app-id", "claude-code", "Governed workload identifier")
	detachFlag := fs.Bool("detach", false, "Spawn background detached process and exit immediately")

	if err := fs.Parse(args); err != nil {
		return err
	}

	watchPID := *pidFlag
	if watchPID <= 0 {
		watchPID = os.Getppid()
	}

	serverURL := *serverFlag
	if serverURL == "" {
		ep := config.ResolveEndpoints()
		serverURL = ep.ControlPlaneURL
	}
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	sessionID := *sessionFlag
	if sessionID == "" {
		sessionID = os.Getenv("BAP_SESSION_ID")
	}
	if sessionID == "" {
		for _, loc := range []string{".bap-session.json", "../.bap-session.json"} {
			if data, err := os.ReadFile(loc); err == nil {
				var sInfo struct {
					SessionID string `json:"session_id"`
				}
				if json.Unmarshal(data, &sInfo) == nil && sInfo.SessionID != "" {
					sessionID = sInfo.SessionID
					break
				}
			}
		}
	}
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-%s-%d", *appFlag, watchPID)
	}

	if *detachFlag {
		exe, err := os.Executable()
		if err != nil {
			exe = "bapedge.exe"
		}
		cmdArgs := []string{
			"watch",
			fmt.Sprintf("--pid=%d", watchPID),
			fmt.Sprintf("--server=%s", serverURL),
			fmt.Sprintf("--session-id=%s", sessionID),
			fmt.Sprintf("--app-id=%s", *appFlag),
		}
		detachedCmd := exec.Command(exe, cmdArgs...)
		detachedCmd.SysProcAttr = getSysProcAttrDetached()
		if err := detachedCmd.Start(); err != nil {
			return fmt.Errorf("failed to start detached watcher: %w", err)
		}
		return nil
	}

	runWatchLoop(watchPID, serverURL, sessionID, *appFlag)
	return nil
}

func sessionMarkerPath(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return filepath.Join(".bap", "sessions", fmt.Sprintf("%x.json", sum[:]))
}

func sessionPIDMarkerPath(pid int) string {
	return filepath.Join(".bap", "sessions", fmt.Sprintf("pid-%d.json", pid))
}

func writeSessionMarker(sessionID, serverURL, appID, username, hostname, initialPrompt string, watchPID int) {
	marker := map[string]any{
		"session_id":  sessionID,
		"server_url":  serverURL,
		"pid":         watchPID,
		"app_id":      appID,
		"user":        username,
		"hostname":    hostname,
		"user_prompt": initialPrompt,
		"started_at":  time.Now().UTC(),
	}
	if data, err := json.MarshalIndent(marker, "", "  "); err == nil {
		// 1. Write per-session isolated marker
		p := sessionMarkerPath(sessionID)
		_ = os.MkdirAll(filepath.Dir(p), 0700)
		_ = os.WriteFile(p, data, 0600)

		// 2. Write per-PID marker
		if watchPID > 0 {
			_ = os.WriteFile(sessionPIDMarkerPath(watchPID), data, 0600)
		}

		// 3. Write workspace session fallback inside .bap/
		_ = os.WriteFile(filepath.Join(".bap", "session.json"), data, 0600)
		// Clean up any stray root marker
		_ = os.Remove(".bap-session.json")
	}
}

func cleanupSessionMarker(sessionID string, watchPID int) {
	if sessionID != "" {
		_ = os.Remove(sessionMarkerPath(sessionID))
	}
	if watchPID > 0 {
		_ = os.Remove(sessionPIDMarkerPath(watchPID))
	}
	_ = os.Remove(filepath.Join(".bap", "session.json"))

	// Clean up legacy .bap-session.json if present
	for _, cand := range []string{".bap-session.json", "../.bap-session.json"} {
		if data, err := os.ReadFile(cand); err == nil {
			var sInfo struct {
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(data, &sInfo) == nil {
				if sInfo.SessionID == "" || sInfo.SessionID == sessionID {
					_ = os.Remove(cand)
				}
			}
		}
	}
	// Purge dead session markers to prevent local state residue
	cleanupStaleSessionMarkers()
}

// cleanupStaleSessionMarkers scans .bap/sessions/ and removes orphaned markers for dead processes.
func cleanupStaleSessionMarkers() {
	sessionsDir := filepath.Join(".bap", "sessions")
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(sessionsDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var marker struct {
			PID       int       `json:"pid"`
			SessionID string    `json:"session_id"`
			StartedAt time.Time `json:"started_at"`
		}
		if err := json.Unmarshal(data, &marker); err == nil {
			if marker.PID > 0 && !isProcessAlive(marker.PID) {
				_ = os.Remove(path)
				if marker.SessionID != "" {
					_ = os.Remove(sessionMarkerPath(marker.SessionID))
				}
			}
		}
	}
}

func runWatchLoop(watchPID int, serverURL, sessionID, appID string) {
	initialPrompt := strings.TrimSpace(os.Getenv("BAP_USER_PROMPT"))

	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	hostname, _ := os.Hostname()

	// 1. Ensure isolated per-session marker exists
	writeSessionMarker(sessionID, serverURL, appID, username, hostname, initialPrompt, watchPID)

	// 2. Enroll session into central control plane (idempotent)
	startPayload := map[string]any{
		"session_id":  sessionID,
		"app_id":      appID,
		"user_id":     username,
		"hostname":    hostname,
		"client_pid":  watchPID,
		"user_prompt": initialPrompt,
	}
	_ = postJSONQuick(serverURL+"/api/v1/sessions/start", startPayload)

	// 3. Continuous Heartbeat and Liveness Monitor
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	deadCheckCount := 0
	sessionFile := sessionMarkerPath(sessionID)
	var lastScannedEpoch int64

	for range ticker.C {
		// If watchPID was not specified at launch, look for it in local session marker
		if watchPID <= 0 {
			if data, err := os.ReadFile(sessionFile); err == nil {
				var sInfo struct {
					PID int `json:"pid"`
				}
				if json.Unmarshal(data, &sInfo) == nil && sInfo.PID > 0 {
					watchPID = sInfo.PID
				}
			}
			if watchPID <= 0 {
				for _, loc := range []string{".bap-session.json", "../.bap-session.json"} {
					if data, err := os.ReadFile(loc); err == nil {
						var sInfo struct {
							PID int `json:"pid"`
						}
						if json.Unmarshal(data, &sInfo) == nil && sInfo.PID > 0 {
							watchPID = sInfo.PID
							break
						}
					}
				}
			}
		}

		// Only check process termination if a valid target PID was specified
		if watchPID > 0 {
			if !isProcessAlive(watchPID) {
				deadCheckCount++
				if deadCheckCount >= 2 {
					// Workload confirmed terminated (exit, Ctrl+C, or window close)
					endPayload := map[string]any{
						"session_id": sessionID,
						"reason":     "Workload process exited cleanly",
					}
					_ = postJSONQuick(serverURL+"/api/v1/sessions/end", endPayload)
					cleanupSessionMarker(sessionID, watchPID)
					return
				}
			} else {
				deadCheckCount = 0
			}
		} else {
			// Fallback: If no target PID, exit only if this specific session's marker was deleted
			if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
				if _, err2 := os.Stat(".bap-session.json"); os.IsNotExist(err2) {
					return
				}
			}
		}

		// Keep alive & pulse heartbeat continuously
		statusHB, reasonHB, scanEpoch := pulseHeartbeat(serverURL, sessionID)
		if scanEpoch > 0 && scanEpoch != lastScannedEpoch {
			lastScannedEpoch = scanEpoch
			if isLocalScanRunning.CompareAndSwap(false, true) {
				go func() {
					defer isLocalScanRunning.Store(false)
					performLocalClientShadowScan(serverURL, sessionID, appID, hostname)
				}()
			}
		}
		if statusHB == "closed" {
			if watchPID > 0 {
				fmt.Fprintf(os.Stderr, "[bapedge watch] 🛑 Session %s STOPPED: Terminating workload (PID: %d)...\n", sessionID, watchPID)
				killProcessPID(watchPID)
			}
			cleanupSessionMarker(sessionID, watchPID)
			return
		}
		syncRevocationsFast(serverURL, "policy.cedar")
		revokedByState := isSessionRevokedInState(sessionID)

		if statusHB == "revoked" || revokedByState {
			reason := reasonHB
			if reason == "" {
				reason = "Session authority revoked by administrator (synced policy state)"
			}
			fmt.Fprintf(os.Stderr, "[bapedge watch] 🚨 Session %s REVOKED by control plane: %s\n", sessionID, reason)
			writeLocalRevoked(sessionID, reason)
			if watchPID > 0 {
				fmt.Fprintf(os.Stderr, "[bapedge watch] ⚡ Terminating revoked agent workload (PID: %d)...\n", watchPID)
				killProcessPID(watchPID)
			}
			cleanupSessionMarker(sessionID, watchPID)
			return
		}
	}
}

func killProcessPID(pid int) {
	if pid <= 0 || pid == os.Getpid() {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid), "/FI", "IMAGENAME ne bapcontrolplane.exe").Run()
	} else {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
		}
	}
}

func writeLocalRevoked(sessionID, reason string) {
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	marker := map[string]any{
		"session_id": sessionID,
		"user_id":    username,
		"status":     "revoked",
		"revoked_at": time.Now().UTC(),
		"reason":     reason,
	}
	if data, err := json.MarshalIndent(marker, "", "  "); err == nil {
		_ = os.WriteFile(".bap-revoked", data, 0600)
		_ = os.WriteFile("../.bap-revoked", data, 0600)
	}
}

func isSessionRevokedInState(sessionID string) bool {
	var data []byte
	var err error
	for _, cand := range []string{filepath.Join(".bap", "policy-state.json"), "policy-state.json", filepath.Join("..", ".bap", "policy-state.json"), filepath.Join("..", "policy-state.json")} {
		if d, e := os.ReadFile(cand); e == nil {
			data = d
			err = nil
			break
		} else {
			err = e
		}
	}
	if err != nil {
		return false
	}
	var st struct {
		KillSwitch      bool     `json:"kill_switch"`
		RevokedSessions []string `json:"revoked_sessions"`
	}
	if json.Unmarshal(data, &st) != nil {
		return false
	}
	if st.KillSwitch {
		return true
	}
	sessLower := strings.ToLower(sessionID)
	for _, rev := range st.RevokedSessions {
		revLower := strings.ToLower(strings.TrimSpace(rev))
		if revLower != "" && (strings.Contains(sessLower, revLower) || strings.Contains(revLower, sessLower)) {
			return true
		}
	}
	return false
}

func pulseHeartbeat(serverURL, sessionID string) (string, string, int64) {
	body, err := json.Marshal(map[string]any{"session_id": sessionID})
	if err != nil {
		return "", "", 0
	}
	client := httptransport.New(2 * time.Second)
	var resp *http.Response
	for attempt := 0; attempt < 2; attempt++ {
		r, err := client.Post(serverURL+"/api/v1/sessions/heartbeat", "application/json", bytes.NewReader(body))
		if err == nil {
			resp = r
			break
		}
		if attempt == 0 {
			time.Sleep(150 * time.Millisecond)
		}
	}
	if resp == nil {
		return "", "", 0
	}
	defer resp.Body.Close()
	var res struct {
		Status    string `json:"status"`
		Action    string `json:"action"`
		Reason    string `json:"reason"`
		ScanEpoch int64  `json:"scan_epoch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err == nil {
		if res.Status == "closed" {
			return "closed", res.Reason, res.ScanEpoch
		}
		if res.Status == "revoked" || res.Action == "terminate" {
			return "revoked", res.Reason, res.ScanEpoch
		}
		return "ok", "", res.ScanEpoch
	}
	return "ok", "", 0
}

func postJSONQuick(url string, payload any) error {
	return postJSONWithRetry(url, payload, 3, 200*time.Millisecond)
}

func postJSONWithRetry(url string, payload any, maxAttempts int, initialBackoff time.Duration) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := httptransport.New(3 * time.Second)
	var lastErr error
	backoff := initialBackoff
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("HTTP status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if attempt < maxAttempts {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	fmt.Fprintf(os.Stderr, "[bapedge watch] Error posting to %s after %d attempts: %v\n", url, maxAttempts, lastErr)
	return lastErr
}

// performLocalClientShadowScan scans the local developer workstation and reports unmanaged assets up to control plane.
func performLocalClientShadowScan(serverURL, sessionID, appID, hostname string) {
	cwd, _ := os.Getwd()
	findings := make([]map[string]any, 0)

	// 1. Scan Local Environment Variables for Standing Secrets
	sensitiveVars := map[string]string{
		"AWS_SECRET_ACCESS_KEY": "AWS Standing Secret",
		"AWS_SESSION_TOKEN":     "AWS Session Token",
		"OPENAI_API_KEY":        "LLM Provider API Key",
		"ANTHROPIC_API_KEY":     "LLM Provider API Key",
		"DATABASE_URL":          "Database Connection String",
		"POSTGRES_PASSWORD":     "Database Password",
		"GITHUB_TOKEN":          "Source Control Token",
	}
	for envKey, category := range sensitiveVars {
		if val := os.Getenv(envKey); strings.TrimSpace(val) != "" {
			masked := "***"
			if len(val) > 6 {
				masked = val[:4] + "...***"
			}
			findings = append(findings, map[string]any{
				"id":                fmt.Sprintf("laptop-env-%s-%d", strings.ToLower(envKey), time.Now().UnixNano()),
				"type":              "UNMANAGED_ENV_VARIABLE",
				"name":              fmt.Sprintf("Local Developer Secret: %s (%s)", envKey, category),
				"target":            envKey,
				"risk_level":        "CRITICAL",
				"risk_score":        0.95,
				"details":           fmt.Sprintf("Laptop environment variable %s contains plaintext credentials (%s). This bypasses BAP's Zero Standing Privilege invariant.", envKey, masked),
				"remediation":       "Migrate to BAP Ephemeral Bounded Grants; remove standing credentials from developer environment.",
				"agent_id":          sessionID,
				"hostname":          hostname,
				"is_managed_by_bap": false,
			})
		}
	}

	// 2. Scan Workspace .env Files
	for _, envName := range []string{".env", ".env.local", ".env.production"} {
		targetFile := filepath.Join(cwd, envName)
		if fi, err := os.Stat(targetFile); err == nil && !fi.IsDir() {
			findings = append(findings, map[string]any{
				"id":                fmt.Sprintf("laptop-file-%s-%d", envName, time.Now().UnixNano()),
				"type":              "UNPROTECTED_ENV_FILE",
				"name":              fmt.Sprintf("Unprotected Secrets File: %s", envName),
				"target":            targetFile,
				"risk_level":        "HIGH",
				"risk_score":        0.75,
				"details":           fmt.Sprintf("Local environment file %s found on developer disk (%d bytes). Plaintext secrets are vulnerable to unauthorized agent reading.", targetFile, fi.Size()),
				"remediation":       "Move secrets to corporate Vault/KMS and ensure file is listed in .gitignore.",
				"agent_id":          sessionID,
				"hostname":          hostname,
				"is_managed_by_bap": false,
			})
		}
	}

	// 3. Scan Local Claude Desktop & Cursor MCP Configs
	mcpPaths := make([]string, 0)
	if appData := os.Getenv("APPDATA"); appData != "" {
		mcpPaths = append(mcpPaths, filepath.Join(appData, "Claude", "claude_desktop_config.json"))
	}
	if home := os.Getenv("USERPROFILE"); home != "" {
		mcpPaths = append(mcpPaths, filepath.Join(home, ".cursor", "mcp.json"))
	}
	if home := os.Getenv("HOME"); home != "" {
		mcpPaths = append(mcpPaths,
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
		)
	}
	mcpPaths = append(mcpPaths, filepath.Join(cwd, ".cursor", "mcp.json"), filepath.Join(cwd, ".vscode", "mcp.json"))

	for _, p := range mcpPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg struct {
			MCPServers map[string]struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"mcpServers"`
		}
		if json.Unmarshal(data, &cfg) == nil {
			for srvName, srvDef := range cfg.MCPServers {
				cmdLine := srvDef.Command + " " + strings.Join(srvDef.Args, " ")
				if !strings.Contains(strings.ToLower(cmdLine), "bapedge") && !strings.Contains(strings.ToLower(cmdLine), "bapmcp") {
					findings = append(findings, map[string]any{
						"id":                fmt.Sprintf("laptop-mcp-%s-%d", srvName, time.Now().UnixNano()),
						"type":              "UNMANAGED_LOCAL_MCP_SERVER",
						"name":              fmt.Sprintf("Shadow MCP Server: %s", srvName),
						"target":            p,
						"risk_level":        "HIGH",
						"risk_score":        0.75,
						"details":           fmt.Sprintf("Local developer MCP server %q executes command %q outside BAP policy governance.", srvName, cmdLine),
						"remediation":       fmt.Sprintf("Wrap %q command with 'bapedge mcp' or register in BAP fleet catalog.", srvName),
						"agent_id":          sessionID,
						"hostname":          hostname,
						"is_managed_by_bap": false,
					})
				}
			}
		}
	}

	if len(findings) > 0 {
		payload := map[string]any{
			"agent_id":         sessionID,
			"hostname":         hostname,
			"workspace_root":   cwd,
			"client_findings": findings,
		}
		_ = postJSONQuick(serverURL+"/api/v1/discovery/shadow-it/scan", payload)
		fmt.Fprintf(os.Stderr, "[bapedge watch] 🛡️ Completed local shadow IT sweep: %d unmanaged assets reported to control plane\n", len(findings))
	}
}
