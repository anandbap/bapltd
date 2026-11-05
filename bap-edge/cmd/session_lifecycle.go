package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
)

const sessionWatcherFreshness = 15 * time.Second

// IsWatcherAlive checks if the detached background watcher for this session is actively pulsing.
func IsWatcherAlive(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	fi, err := os.Stat(watcherLivenessPath(sessionID))
	return err == nil && time.Since(fi.ModTime()) < sessionWatcherFreshness
}

// IsSessionActive checks if the session is currently known and active locally.
func IsSessionActive(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	if IsWatcherAlive(sessionID) {
		return true
	}
	// Check session marker in state.SessionsDir()
	p := sessionMarkerPath(sessionID)
	if _, err := os.Stat(p); err == nil {
		return true
	}
	// Check workspace fallback
	if data, err := os.ReadFile(state.WorkspaceSessionPath()); err == nil {
		var sInfo struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal(data, &sInfo) == nil && strings.EqualFold(sInfo.SessionID, sessionID) {
			return true
		}
	}
	return false
}

// EnsureSessionStarted registers the session with the Central Control Plane if not already active.
// It links the session to workstation enrollment, mints/derives the Session SVID,
// writes local session markers, and spawns the background heartbeat monitor.
func EnsureSessionStarted(sessionID, appID string, clientPID int, initialPrompt string) error {
	normAppID := normalizeClientAppID(appID)
	if normAppID == "" {
		normAppID = "claude-code"
	}

	if clientPID <= 0 {
		clientPID = os.Getppid()
	}

	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-%s-pid-%d", normAppID, clientPID)
	}

	// 1. If watcher is alive and marker exists, it's already running cleanly
	if IsWatcherAlive(sessionID) {
		return nil
	}

	// 2. Check local revocation / kill-switch
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
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
						reason = "User access has been revoked by enterprise security policy"
					}
					return fmt.Errorf("Session startup BLOCKED: %s", reason)
				}
			}
		}
	}

	if isSessionRevokedInState(sessionID) {
		return fmt.Errorf("Session startup BLOCKED: session %s is revoked by enterprise policy", sessionID)
	}

	// 3. Resolve Control Plane Endpoint
	ep := config.ResolveEndpoints()
	serverURL := ep.ControlPlaneURL
	if serverURL == "" {
		serverURL = config.DefaultControlPlaneURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	// 4. Resolve Identity & Workstation SVID Anchor from enrolled credentials
	var credEmail string
	var credSPIFFE string
	var instanceID string
	if data, err := os.ReadFile(DefaultCredentialsPath()); err == nil {
		var creds StoredCredentials
		if json.Unmarshal(data, &creds) == nil {
			credEmail = creds.UserEmail
			credSPIFFE = creds.SPIFFEID
			instanceID = creds.InstanceID
		}
	}
	if credEmail == "" {
		_, credEmail, _ = resolveLocalIdentity()
	}
	if instanceID == "" {
		instanceID = resolveDefaultInstanceID("")
	}
	if credSPIFFE == "" {
		credSPIFFE = fmt.Sprintf("spiffe://bap.local/workstation/%s", instanceID)
	}

	sessionSVID := fmt.Sprintf("spiffe://bap.internal/workstation/%s/session/%s", instanceID, sessionID)
	hostname, _ := os.Hostname()

	// 5. Pre-flight registration with Central Control Plane
	startPayload := map[string]any{
		"session_id":            sessionID,
		"app_id":                normAppID,
		"instance_id":           instanceID,
		"resource_id":           instanceID,
		"user_id":               username,
		"hostname":              hostname,
		"client_pid":            clientPID,
		"user_prompt":           initialPrompt,
		"session_svid":          sessionSVID,
		"workstation_spiffe_id": credSPIFFE,
		"spiffe_id":             credSPIFFE,
		"reporting_layer":       "plugin",
	}
	if credEmail != "" && credEmail != "NA" {
		startPayload["user_email"] = credEmail
	}

	body, _ := json.Marshal(startPayload)
	client := httptransport.New(3 * time.Second)
	resp, err := client.Post(serverURL+"/api/v1/sessions/start", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[EnsureSessionStarted] POST %s/api/v1/sessions/start error: %v\n", serverURL, err)
	}
	if err == nil && resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			var errResp struct {
				Error string `json:"error"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			reason := errResp.Error
			if reason == "" {
				reason = "User access has been revoked by enterprise security administrator"
			}
			writeLocalRevoked(sessionID, reason)
			return fmt.Errorf("Session startup BLOCKED: %s", reason)
		}
	}

	// 6. Persist local session markers
	writeSessionMarker(sessionID, serverURL, normAppID, username, hostname, initialPrompt, clientPID, instanceID)

	// 7. Spawn detached background watcher (heartbeat monitor) if not in test env
	if !isTestEnv() && !IsWatcherAlive(sessionID) {
		exe, err := os.Executable()
		if err != nil {
			exe = "bapedge.exe"
		}
		cmdArgs := []string{
			"watch",
			fmt.Sprintf("--pid=%d", clientPID),
			fmt.Sprintf("--server=%s", serverURL),
			fmt.Sprintf("--session-id=%s", sessionID),
			fmt.Sprintf("--app-id=%s", normAppID),
			fmt.Sprintf("--instance-id=%s", instanceID),
		}
		detachedCmd := exec.Command(exe, cmdArgs...)
		detachedCmd.SysProcAttr = getSysProcAttrDetached()
		_ = detachedCmd.Start()
	}

	return nil
}

// EnsureSessionEnded gracefully notifies Control Plane that the agent session ended,
// terminates the heartbeat watcher, and removes local markers.
func EnsureSessionEnded(sessionID, reason string) error {
	if sessionID == "" {
		return nil
	}
	ep := config.ResolveEndpoints()
	serverURL := ep.ControlPlaneURL
	if serverURL == "" {
		serverURL = config.DefaultControlPlaneURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	endPayload := map[string]any{
		"session_id": sessionID,
		"reason":     reason,
	}
	_ = postJSONQuick(serverURL+"/api/v1/sessions/end", endPayload)
	cleanupSessionMarker(sessionID, 0)
	_ = os.Remove(watcherLivenessPath(sessionID))
	return nil
}

// SubmitUserPrompt forwards an intercepted prompt to the Control Plane for intent & risk analysis.
func SubmitUserPrompt(sessionID, appID, prompt string) error {
	if strings.TrimSpace(prompt) == "" {
		return nil
	}
	ep := config.ResolveEndpoints()
	serverURL := ep.ControlPlaneURL
	if serverURL == "" {
		serverURL = config.DefaultControlPlaneURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	normAppID := normalizeClientAppID(appID)
	h := sha256.Sum256([]byte(prompt))
	promptHash := hex.EncodeToString(h[:])

	primaryIntent := "FEATURE_ENHANCEMENT"
	low := strings.ToLower(prompt)
	if strings.Contains(low, "bug") || strings.Contains(low, "fix") || strings.Contains(low, "error") || strings.Contains(low, "fail") {
		primaryIntent = "BUG_FIX"
	} else if strings.Contains(low, "test") || strings.Contains(low, "quality") || strings.Contains(low, "verify") {
		primaryIntent = "TEST_VERIFICATION"
	} else if strings.Contains(low, "doc") || strings.Contains(low, "readme") || strings.Contains(low, "guide") {
		primaryIntent = "DOCUMENTATION"
	} else if strings.Contains(low, "security") || strings.Contains(low, "vuln") || strings.Contains(low, "audit") {
		primaryIntent = "SECURITY_REMEDIATION"
	}

	promptPayload := map[string]any{
		"session_id":             sessionID,
		"app_id":                 normAppID,
		"user_prompt":            prompt,
		"producer":               "native-plugin-hook",
		"prompt_hash":            promptHash,
		"prompt_capture_enabled": true,
		"intent": map[string]any{
			"primary":            primaryIntent,
			"confidence":         0.92,
			"source":             "claude-user-prompt-submit",
			"classifier_version": "v1.0",
			"prompt_hash":        promptHash,
			"prompt_captured":    true,
		},
	}
	incrementSessionMarkerPromptCount(sessionID, prompt)
	return postJSONQuick(serverURL+"/api/v1/sessions/prompt", promptPayload)
}

func incrementSessionMarkerPromptCount(sessionID, prompt string) {
	if sessionID == "" {
		return
	}
	p := sessionMarkerPath(sessionID)
	data, err := os.ReadFile(p)
	if err == nil {
		var marker map[string]any
		if json.Unmarshal(data, &marker) == nil {
			if strings.TrimSpace(prompt) != "" {
				marker["user_prompt"] = prompt
			}
			curCount := 0
			if v, ok := marker["prompt_count"].(float64); ok {
				curCount = int(v)
			}
			marker["prompt_count"] = curCount + 1
			if out, err := json.MarshalIndent(marker, "", "  "); err == nil {
				_ = os.WriteFile(p, out, 0600)
			}
		}
	}
}

// Helper extraction functions
func extractClientPID(payload map[string]any) int {
	if v, ok := payload["client_pid"].(float64); ok && v > 0 {
		return int(v)
	}
	if v, ok := payload["client_pid"].(int); ok && v > 0 {
		return v
	}
	if v, ok := payload["pid"].(float64); ok && v > 0 {
		return int(v)
	}
	if v, ok := payload["pid"].(int); ok && v > 0 {
		return v
	}
	return os.Getppid()
}

func extractPrompt(payload map[string]any) string {
	for _, key := range []string{"prompt", "user_prompt", "initial_prompt", "message"} {
		if v, ok := payload[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isAgentSource(source string) bool {
	norm := strings.ToLower(strings.TrimSpace(source))
	return norm == "claude-code" || norm == "claude" ||
		norm == "copilot" || norm == "github-copilot" ||
		norm == "antigravity" || norm == "agy" ||
		norm == "opencode" || norm == "open-code" ||
		norm == "codex" || norm == "openai-codex" ||
		norm == "cursor" || norm == "gemini"
}

