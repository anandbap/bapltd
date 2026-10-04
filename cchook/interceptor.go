package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const intentClassifierVersion = "bap-intent-rules-v1"

// IntentClassification is the deterministic, locally-derived mission context
// sent by BAP Edge. It is evidence for observability and correlation; it is
// never used as authorization by itself.
type IntentClassification struct {
	Primary           string   `json:"primary"`
	Secondary         []string `json:"secondary,omitempty"`
	Tags              []string `json:"tags,omitempty"`
	Confidence        float64  `json:"confidence"`
	ClassifierVersion string   `json:"classifier_version"`
	Source            string   `json:"source"`
	Evidence          []string `json:"evidence,omitempty"`
}

type intentRule struct {
	Category string
	Phrases  []intentPhrase
}

type intentPhrase struct {
	Text   string
	Label  string
	Weight int
}

type intentTagRule struct {
	Tag     string
	Phrases []string
}

var intentRules = []intentRule{
	{Category: "BUG_FIX", Phrases: []intentPhrase{{" fix bug ", "fix bug", 8}, {" bug fix ", "bug fix", 8}, {" fix the bug ", "fix the bug", 8}, {" bugfix ", "bugfix", 8}, {" regression ", "regression", 5}, {" broken ", "broken", 4}, {" defect ", "defect", 4}, {" bug ", "bug", 4}, {" failing ", "failing", 3}, {" error ", "error", 2}, {" fix ", "fix", 2}}},
	{Category: "DATABASE_CHANGE", Phrases: []intentPhrase{{" update db ", "update db", 7}, {" update database ", "update database", 7}, {" database migration ", "database migration", 7}, {" migrate database ", "migrate database", 7}, {" schema change ", "schema change", 6}, {" alter table ", "alter table", 6}, {" database ", "database", 3}, {" db ", "db", 3}, {" sql ", "sql", 2}}},
	{Category: "FEATURE_ENHANCEMENT", Phrases: []intentPhrase{{" new feature ", "new feature", 7}, {" add feature ", "add feature", 6}, {" enhance ui ", "enhance ui", 6}, {" ui enhancement ", "ui enhancement", 6}, {" enhancement ", "enhancement", 4}, {" enhance ", "enhance", 4}, {" improve ", "improve", 3}, {" implement ", "implement", 3}, {" add ", "add", 2}, {" build ", "build", 2}, {" create ", "create", 2}}},
	{Category: "INVESTIGATION", Phrases: []intentPhrase{{" root cause ", "root cause", 7}, {" investigate ", "investigate", 6}, {" analyze ", "analyze", 5}, {" diagnose ", "diagnose", 5}, {" find out ", "find out", 4}, {" understand ", "understand", 3}, {" inspect ", "inspect", 2}, {" review ", "review", 2}}},
	{Category: "REFACTOR", Phrases: []intentPhrase{{" refactor ", "refactor", 7}, {" clean up code ", "clean up code", 5}, {" restructure ", "restructure", 5}, {" simplify code ", "simplify code", 4}, {" optimize ", "optimize", 3}}},
	{Category: "TEST_VERIFICATION", Phrases: []intentPhrase{{" write tests ", "write tests", 7}, {" add tests ", "add tests", 7}, {" test coverage ", "test coverage", 6}, {" verify ", "verify", 4}, {" validate ", "validate", 4}, {" test ", "test", 3}}},
	{Category: "DOCUMENTATION", Phrases: []intentPhrase{{" update readme ", "update readme", 7}, {" write docs ", "write docs", 7}, {" documentation ", "documentation", 6}, {" document ", "document", 5}, {" readme ", "readme", 4}}},
	{Category: "MIGRATION", Phrases: []intentPhrase{{" dependency update ", "dependency update", 7}, {" upgrade dependency ", "upgrade dependency", 7}, {" upgrade framework ", "upgrade framework", 7}, {" migration ", "migration", 5}, {" migrate ", "migrate", 5}, {" modernize ", "modernize", 4}, {" upgrade ", "upgrade", 4}, {" dependency ", "dependency", 3}}},
	{Category: "DEPLOYMENT_RELEASE", Phrases: []intentPhrase{{" deploy to production ", "deploy to production", 8}, {" production deployment ", "production deployment", 8}, {" deployment ", "deployment", 5}, {" release ", "release", 5}, {" deploy ", "deploy", 5}, {" rollout ", "rollout", 4}, {" build pipeline ", "build pipeline", 3}}},
	{Category: "WORK_MANAGEMENT", Phrases: []intentPhrase{{" jira ", "jira", 6}, {" create ticket ", "create ticket", 6}, {" update ticket ", "update ticket", 6}, {" pull request ", "pull request", 5}, {" open pr ", "open pr", 5}, {" create pr ", "create pr", 5}, {" work item ", "work item", 4}}},
	{Category: "SECURITY_REMEDIATION", Phrases: []intentPhrase{{" security fix ", "security fix", 8}, {" remediate vulnerability ", "remediate vulnerability", 8}, {" vulnerability ", "vulnerability", 6}, {" cve ", "cve", 6}, {" security ", "security", 3}, {" permission ", "permission", 2}}},
}

var intentTagRules = []intentTagRule{
	{Tag: "API", Phrases: []string{" api ", " endpoint ", " rest ", " graphql "}},
	{Tag: "CUSTOMER_FACING", Phrases: []string{" customer ", " client facing ", " user facing "}},
	{Tag: "DATABASE", Phrases: []string{" db ", " database ", " schema ", " sql ", " table "}},
	{Tag: "INFRASTRUCTURE", Phrases: []string{" terraform ", " kubernetes ", " k8s ", " cloud ", " infrastructure "}},
	{Tag: "PRODUCTION", Phrases: []string{" production ", " prod ", " release ", " deploy "}},
	{Tag: "SECURITY", Phrases: []string{" security ", " vulnerability ", " cve ", " credential ", " permission ", " secret "}},
	{Tag: "UI", Phrases: []string{" ui ", " frontend ", " dashboard ", " screen ", " css ", " ux "}},
}

func normalizedIntentText(prompt string) string {
	lower := strings.ToLower(prompt)
	var b strings.Builder
	b.Grow(len(lower) + 2)
	b.WriteByte(' ')
	lastSpace := true
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastSpace = false
		} else if !lastSpace {
			b.WriteByte(' ')
			lastSpace = true
		}
	}
	if !lastSpace {
		b.WriteByte(' ')
	}
	return b.String()
}

func classifyIntent(prompt string) IntentClassification {
	result := IntentClassification{
		Primary:           "UNKNOWN",
		Confidence:        0,
		ClassifierVersion: intentClassifierVersion,
		Source:            "claude-user-prompt-submit",
	}
	normalized := normalizedIntentText(prompt)
	if strings.TrimSpace(normalized) == "" {
		result.Evidence = []string{"empty-or-unavailable-prompt"}
		return result
	}

	type scoredIntent struct {
		category string
		score    int
		order    int
	}
	scored := make([]scoredIntent, 0, len(intentRules))
	for order, rule := range intentRules {
		score := 0
		for _, phrase := range rule.Phrases {
			if strings.Contains(normalized, phrase.Text) {
				score += phrase.Weight
				result.Evidence = append(result.Evidence, rule.Category+":"+phrase.Label)
			}
		}
		if rule.Category == "BUG_FIX" && strings.Contains(normalized, " fix ") && strings.Contains(normalized, " bug ") {
			score += 8
			result.Evidence = append(result.Evidence, "BUG_FIX:fix+bug")
		}
		if score > 0 {
			scored = append(scored, scoredIntent{category: rule.Category, score: score, order: order})
		}
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].order < scored[j].order
		}
		return scored[i].score > scored[j].score
	})
	if len(scored) > 0 {
		result.Primary = scored[0].category
		confidence := 0.62 + float64(scored[0].score)*0.04
		if confidence > 0.98 {
			confidence = 0.98
		}
		if len(scored) > 1 && scored[0].score-scored[1].score <= 1 && confidence > 0.72 {
			confidence = 0.72
		}
		result.Confidence = confidence
		for _, item := range scored[1:] {
			if item.score >= 2 && len(result.Secondary) < 3 {
				result.Secondary = append(result.Secondary, item.category)
			}
		}
	} else {
		result.Evidence = append(result.Evidence, "no-rule-match")
	}

	for _, rule := range intentTagRules {
		for _, phrase := range rule.Phrases {
			if strings.Contains(normalized, phrase) {
				result.Tags = append(result.Tags, rule.Tag)
				break
			}
		}
	}
	return result
}

func shouldCaptureUserPrompt() bool {
	if value := strings.TrimSpace(os.Getenv("BAP_CAPTURE_USER_PROMPT")); value != "" {
		if enabled, err := strconv.ParseBool(value); err == nil {
			return enabled
		}
	}
	for _, cfgPath := range []string{filepath.Join(".bap", "bap-config.json"), filepath.Join(".bap", "config.json"), "bap-config.json", "../bap-config.json"} {
		if cfgData, err := os.ReadFile(cfgPath); err == nil {
			var cfg struct {
				CaptureUserPrompt *bool `json:"capture_user_prompt"`
			}
			if json.Unmarshal(cfgData, &cfg) == nil && cfg.CaptureUserPrompt != nil {
				return *cfg.CaptureUserPrompt
			}
		}
	}
	// Preserve the current prototype/demo behavior unless enterprise policy
	// explicitly disables raw prompt retention.
	return true
}

func promptPathForSession(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return filepath.Join(".bap", "prompts", fmt.Sprintf("%x.txt", sum[:]))
}

func writeSessionPrompt(sessionID, prompt string) {
	if sessionID == "" || prompt == "" {
		return
	}
	path := promptPathForSession(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err == nil {
		_ = os.WriteFile(path, []byte(prompt), 0600)
	}
}

//go:embed embedded_ca.crt
var embeddedCACert []byte

func getHTTPClient() *http.Client {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(embeddedCACert) > 0 {
		roots.AppendCertsFromPEM(embeddedCACert)
	}
	path := os.Getenv("BAP_CA_CERT")
	if path == "" {
		for _, cand := range []string{"bap-root-ca.crt", "controlplane-cert.pem", "../bap-root-ca.crt", "../controlplane-cert.pem", "../../controlplane-cert.pem"} {
			if _, err := os.Stat(cand); err == nil {
				path = cand
				break
			}
		}
	}
	if path != "" {
		if pem, err := os.ReadFile(path); err == nil {
			roots.AppendCertsFromPEM(pem)
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Timeout:   2 * time.Second,
		Transport: tr,
	}
}

// ToolInput represents the input object from Claude Code.
// Supports both command-execution (Bash) and direct file tools (Read, View, Edit, Write).
type ToolInput struct {
	Command  string `json:"command,omitempty"`
	FilePath string `json:"file_path,omitempty"`
	Path     string `json:"path,omitempty"`
}

// HookPayload represents the Claude Code lifecycle event payload (SessionStart, UserPromptSubmit, PreToolUse).
type HookPayload struct {
	HookEventName string    `json:"hook_event_name"`
	ToolName      string    `json:"tool_name,omitempty"`
	ToolInput     ToolInput `json:"tool_input,omitempty"`
	UserPrompt    string    `json:"user_prompt,omitempty"`
	Prompt        string    `json:"prompt,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
}

// HookSpecificOutput represents the PreToolUse decision schema.
type HookSpecificOutput struct {
	HookEventName            string     `json:"hookEventName"`
	PermissionDecision       string     `json:"permissionDecision"` // "allow" or "deny"
	PermissionDecisionReason string     `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string     `json:"additionalContext,omitempty"`
	UpdatedInput             *ToolInput `json:"updatedInput,omitempty"`
}

// HookResponse is the top-level response expected by Claude Code.
type HookResponse struct {
	Continue           *bool              `json:"continue,omitempty"`
	StopReason         string             `json:"stopReason,omitempty"`
	SystemMessage      string             `json:"systemMessage,omitempty"`
	Decision           string             `json:"decision,omitempty"`
	Reason             string             `json:"reason,omitempty"`
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

// ExecResponse represents the JSON output from ltd-agent / bapedge exec or check.
type ExecResponse struct {
	Allowed      bool   `json:"allowed"`
	Output       string `json:"output,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Suggestion   string `json:"suggestion,omitempty"`
	DecisionOnly bool   `json:"decision_only,omitempty"`
}

// unwrapBrokerCommand recognizes only the exact command shape emitted by this
// hook. Agent-authored lookalikes are never trusted: the embedded command is
// decoded, bound to the current session, and sent through Cedar again.
func unwrapBrokerCommand(command, expectedSessionID string) (string, bool, error) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return command, false, nil
	}
	executable := strings.Trim(fields[0], `"'`)
	executable = filepath.Base(strings.ReplaceAll(executable, `\`, "/"))
	switch strings.ToLower(executable) {
	case "bapedge", "bapedge.exe", "ltd-agent", "ltd-agent.exe":
	default:
		return command, false, nil
	}
	if len(fields) != 8 || fields[1] != "exec" || fields[2] != "--source" || fields[3] != "claude-code" || fields[4] != "--session-id" || fields[6] != "--cmd-b64" {
		return "", true, fmt.Errorf("untrusted BAPEdge invocation: expected the broker-owned exec wrapper")
	}
	if expectedSessionID == "" || fields[5] != expectedSessionID {
		return "", true, fmt.Errorf("untrusted BAPEdge invocation: session binding mismatch")
	}
	payload, err := base64.StdEncoding.DecodeString(fields[7])
	if err != nil {
		return "", true, fmt.Errorf("untrusted BAPEdge invocation: invalid command payload")
	}
	decoded := strings.TrimSpace(string(payload))
	if decoded == "" {
		return "", true, fmt.Errorf("untrusted BAPEdge invocation: empty command payload")
	}
	return decoded, true, nil
}

func resolveServerURL() string {
	if s := os.Getenv("BAP_SERVER_URL"); s != "" {
		return strings.TrimRight(s, "/")
	}
	cfgCandidates := []string{
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
		"../bap-config.json",
	}
	if exePath, err := os.Executable(); err == nil {
		cfgCandidates = append(cfgCandidates, filepath.Join(filepath.Dir(exePath), "bap-config.json"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		cfgCandidates = append(cfgCandidates, filepath.Join(home, ".bap", "bap-config.json"))
	}
	for _, cfgPath := range cfgCandidates {
		if cfgData, err := os.ReadFile(cfgPath); err == nil {
			var cfg struct {
				ControlPlaneURL string `json:"controlplane_url"`
			}
			if json.Unmarshal(cfgData, &cfg) == nil && cfg.ControlPlaneURL != "" {
				return strings.TrimRight(cfg.ControlPlaneURL, "/")
			}
		}
	}
	return "http://localhost:8080"
}

func resolveEnforcementMode() string {
	if m := os.Getenv("BAP_MODE"); m != "" {
		return strings.ToLower(strings.TrimSpace(m))
	}
	cfgCandidates := []string{
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
		"../bap-config.json",
	}
	for _, cfgPath := range cfgCandidates {
		if cfgData, err := os.ReadFile(cfgPath); err == nil {
			var cfg struct {
				EnforcementMode string `json:"enforcement_mode"`
			}
			if json.Unmarshal(cfgData, &cfg) == nil && cfg.EnforcementMode != "" {
				return strings.ToLower(strings.TrimSpace(cfg.EnforcementMode))
			}
		}
	}
	return "enforce"
}

func isProtectedBAPAsset(pathStr string) bool {
	lower := strings.ToLower(filepath.ToSlash(pathStr))
	protected := []string{
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
	for _, p := range protected {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isTamperingCommand(cmdStr string) (bool, string) {
	lower := strings.ToLower(filepath.ToSlash(cmdStr))
	protected := []string{
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
	destructive := []string{
		"rm ", "rm -", "del ", "erase ", "remove-item", "unlink", "rmdir", "rd /", "rd ",
		">", ">>", "set-content", "out-file", "add-content", "truncate", "sed ",
		"ren ", "rename ", "move ", "mv ", "copy ", "cp ", "chmod ", "attrib ",
	}
	for _, p := range protected {
		if strings.Contains(lower, p) {
			for _, d := range destructive {
				if strings.Contains(lower, d) {
					return true, fmt.Sprintf("Security Invariant Violation: Direct modification, deletion, or tampering with BAP protected asset %q is strictly forbidden.", p)
				}
			}
		}
	}
	return false, ""
}

func sessionMarkerPathForPID(pid int) string {
	return filepath.Join(".bap", "sessions", fmt.Sprintf("pid-%d.json", pid))
}

func resolveSessionID(payload HookPayload) string {
	if sessionID := os.Getenv("BAP_SESSION_ID"); sessionID != "" {
		return sessionID
	}
	if sessionID := os.Getenv("LTD_SESSION_ID"); sessionID != "" {
		return sessionID
	}
	if payload.SessionID != "" {
		return payload.SessionID
	}

	// 1. Check PID-specific session marker for concurrent Claude session isolation
	ppid := os.Getppid()
	for _, cand := range []string{sessionMarkerPathForPID(ppid), filepath.Join("..", sessionMarkerPathForPID(ppid))} {
		if data, err := os.ReadFile(cand); err == nil {
			var info struct {
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(data, &info) == nil && info.SessionID != "" {
				return info.SessionID
			}
		}
	}

	// 2. Check legacy workspace marker files
	for _, loc := range []string{".bap-session.json", "../.bap-session.json", "cchook/.bap-session.json"} {
		if data, err := os.ReadFile(loc); err == nil {
			var info struct {
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(data, &info) == nil && info.SessionID != "" {
				return info.SessionID
			}
		}
	}
	return ""
}

func remotelyRevoked(serverURL, sessionID string) (bool, string) {
	if serverURL == "" || sessionID == "" {
		return false, ""
	}
	resp, err := getHTTPClient().Get(strings.TrimRight(serverURL, "/") + "/api/v1/control/revocations")
	if err != nil || resp == nil {
		return false, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, ""
	}
	var state struct {
		KillSwitch      bool     `json:"kill_switch"`
		RevokedSessions []string `json:"revoked_sessions"`
		RevokedUsers    []string `json:"revoked_users"`
	}
	if json.NewDecoder(resp.Body).Decode(&state) != nil {
		return false, ""
	}
	if state.KillSwitch {
		return true, "fleet authority is frozen by an administrator"
	}
	for _, revoked := range state.RevokedSessions {
		if strings.EqualFold(strings.TrimSpace(revoked), sessionID) {
			return true, fmt.Sprintf("session %q authority has been revoked by an administrator", sessionID)
		}
	}
	currentUser := os.Getenv("USERNAME")
	if currentUser == "" {
		currentUser = os.Getenv("USER")
	}
	if currentUser != "" {
		for _, ru := range state.RevokedUsers {
			if strings.EqualFold(strings.TrimSpace(ru), currentUser) {
				return true, fmt.Sprintf("user %q access has been revoked by an administrator", currentUser)
			}
		}
	}
	return false, ""
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

func isStartupBlocked() (bool, string) {
	// Check .bap-revoked
	for _, cand := range []string{".bap-revoked", "../.bap-revoked"} {
		if data, err := os.ReadFile(cand); err == nil {
			var info struct {
				KillSwitch bool   `json:"kill_switch"`
				AppID      string `json:"app_id"`
				Reason     string `json:"reason"`
			}
			if json.Unmarshal(data, &info) == nil {
				if info.KillSwitch || info.AppID == "claude-code" || info.AppID == "*" {
					reason := info.Reason
					if reason == "" {
						reason = "Enterprise emergency kill-switch is active"
					}
					return true, reason
				}
			}
		}
	}
	// Check policy-state.json
	for _, cand := range []string{filepath.Join(".bap", "policy-state.json"), filepath.Join("..", ".bap", "policy-state.json"), "policy-state.json", "../policy-state.json"} {
		if data, err := os.ReadFile(cand); err == nil {
			var st struct {
				KillSwitch bool `json:"kill_switch"`
			}
			if json.Unmarshal(data, &st) == nil && st.KillSwitch {
				return true, "Emergency kill-switch is active across the fleet"
			}
		}
	}
	return false, ""
}

func handleSessionStartHook(payload HookPayload) {
	ppid := os.Getppid()

	// 1. Check if local kill-switch or freeze blocks startup
	if blocked, reason := isStartupBlocked(); blocked {
		fmt.Fprintf(os.Stderr, "[BAP ZERO-TRUST] 🚨 New Claude Code session BLOCKED: %s\n", reason)
		os.Exit(2)
	}

	// A governed launcher owns the session ID and watcher lifecycle. Claude also
	// supplies its own hook session ID; preferring that value created a second
	// session and a second watcher for the same process.
	sessionID := os.Getenv("BAP_SESSION_ID")
	if sessionID == "" {
		// Check PID-specific marker already written by launcher or bapedge session-start
		if existingID := resolveSessionID(HookPayload{}); existingID != "" {
			sessionID = existingID
		}
	}
	launcherOwnsWatcher := sessionID != ""
	if sessionID == "" {
		sessionID = payload.SessionID
	}
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-claude-pid-%d", ppid)
	}

	serverURL := resolveServerURL()

	// 2. Notify control plane of session start (only if not already registered by launcher)
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	startPayload := map[string]any{
		"session_id": sessionID,
		"app_id":     "claude-code",
		"user_id":    username,
		"hostname":   hostname,
		"client_pid": ppid,
	}
	if !launcherOwnsWatcher {
		if body, err := json.Marshal(startPayload); err == nil {
			client := getHTTPClient()
			resp, err := client.Post(serverURL+"/api/v1/sessions/start", "application/json", bytes.NewReader(body))
			if err == nil && resp != nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusForbidden {
					_ = os.Remove(".bap-session.json")
					fmt.Fprintln(os.Stderr, "[BAP ZERO-TRUST] 🚨 New Claude Code session BLOCKED by enterprise security policy (kill-switch or app revocation active).")
					os.Exit(2)
				}
			}
		}
	}

	marker := map[string]any{
		"session_id": sessionID,
		"server_url": serverURL,
		"pid":        ppid,
		"app_id":     "claude-code",
		"started_at": time.Now().UTC(),
	}
	if data, err := json.MarshalIndent(marker, "", "  "); err == nil {
		pMarker := sessionMarkerPathForPID(ppid)
		_ = os.MkdirAll(filepath.Dir(pMarker), 0700)
		_ = os.WriteFile(pMarker, data, 0600)
		_ = os.WriteFile(filepath.Join(".bap", "session.json"), data, 0600)
		_ = os.Remove(".bap-session.json")
	}

	// Launch detached bapedge watch thread if not already managed by launcher
	ltdBin := findBinary("bapedge.exe")
	if ltdBin == "" {
		ltdBin = findBinary("bapedge")
	}
	if ltdBin != "" && !launcherOwnsWatcher {
		wCmd := exec.Command(ltdBin, "watch", fmt.Sprintf("--pid=%d", ppid), fmt.Sprintf("--server=%s", serverURL), fmt.Sprintf("--session-id=%s", sessionID), "--detach")
		_ = wCmd.Start()
	}

	os.Stdout.WriteString("{\"status\":\"ok\"}\n")
	os.Exit(0)
}

func isSessionRevoked(serverURL, sessionID string) (bool, string) {
	// 1. Check local .bap-revoked marker file (0ms)
	for _, cand := range []string{".bap-revoked", "../.bap-revoked", "cchook/.bap-revoked"} {
		if data, err := os.ReadFile(cand); err == nil {
			var info struct {
				SessionID string `json:"session_id"`
				UserID    string `json:"user_id"`
				Reason    string `json:"reason"`
			}
			if json.Unmarshal(data, &info) == nil {
				currentUser := os.Getenv("USERNAME")
				if currentUser == "" {
					currentUser = os.Getenv("USER")
				}
				userMatch := info.UserID != "" && strings.EqualFold(info.UserID, currentUser)
				sessMatch := info.SessionID != "" && (strings.EqualFold(info.SessionID, sessionID) || strings.Contains(strings.ToLower(sessionID), strings.ToLower(info.SessionID)))
				if userMatch || sessMatch || (info.SessionID == "" && info.UserID == "") {
					reason := info.Reason
					if reason == "" {
						reason = "User access revoked by security administrator (local tombstone marker active)"
					}
					return true, reason
				}
			} else {
				return true, "Access revoked by security administrator"
			}
		}
	}

	// 2. Check local policy-state.json (0ms)
	for _, cand := range []string{filepath.Join(".bap", "policy-state.json"), filepath.Join("..", ".bap", "policy-state.json"), "policy-state.json", "../policy-state.json", "bap-edge/policy-state.json"} {
		if data, err := os.ReadFile(cand); err == nil {
			var st struct {
				KillSwitch      bool     `json:"kill_switch"`
				RevokedSessions []string `json:"revoked_sessions"`
			}
			if json.Unmarshal(data, &st) == nil {
				if st.KillSwitch {
					return true, "Emergency kill-switch is active across the fleet"
				}
				if sessionID != "" {
					sessLower := strings.ToLower(sessionID)
					for _, rev := range st.RevokedSessions {
						revLower := strings.ToLower(strings.TrimSpace(rev))
						if revLower != "" && (strings.Contains(sessLower, revLower) || strings.Contains(revLower, sessLower)) {
							return true, fmt.Sprintf("Session %q authority revoked by administrator", sessionID)
						}
					}
				}
			}
		}
	}

	// 3. Fast remote query to control plane
	return remotelyRevoked(serverURL, sessionID)
}

func outputPromptBlocked(sessionID, reason string) {
	if reason == "" {
		reason = "Session authority has been revoked by enterprise security administrator."
	}
	alertMsg := fmt.Sprintf("[BAP ZERO-TRUST] Session %s is REVOKED. Authority burned: no further user prompts will be accepted.", sessionID)
	fmt.Fprintln(os.Stderr, alertMsg)
	fmt.Fprintf(os.Stderr, "[SECURITY ALERT] Reason: %s\n", reason)

	resp := map[string]any{
		"continue":      false,
		"stopReason":    fmt.Sprintf("[BAP REVOKED] %s", reason),
		"systemMessage": alertMsg,
		"decision":      "block",
		"reason":        reason,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)

	ppid := os.Getppid()
	if ppid > 0 {
		fmt.Fprintf(os.Stderr, "[BAP ZERO-TRUST] ⚡ Terminating rogue agent process (PID: %d)...\n", ppid)
		killProcessPID(ppid)
	}
	for _, loc := range []string{".bap-session.json", "../.bap-session.json"} {
		if data, err := os.ReadFile(loc); err == nil {
			var sInfo struct {
				PID int `json:"pid"`
			}
			if json.Unmarshal(data, &sInfo) == nil && sInfo.PID > 0 {
				killProcessPID(sInfo.PID)
			}
		}
	}

	os.Exit(2)
}

func handleUserPromptHook(payload HookPayload) {
	prompt := strings.TrimSpace(payload.UserPrompt)
	if prompt == "" {
		prompt = strings.TrimSpace(payload.Prompt)
	}
	intent := classifyIntent(prompt)
	promptDigest := sha256.Sum256([]byte(prompt))
	promptHash := fmt.Sprintf("%x", promptDigest[:])
	capturePrompt := shouldCaptureUserPrompt()

	serverURL := resolveServerURL()
	sessionID := resolveSessionID(payload)

	// Zero-Trust Revocation Check: STOP taking user inputs if revoked
	if revoked, reason := isSessionRevoked(serverURL, sessionID); revoked {
		outputPromptBlocked(sessionID, reason)
		return
	}

	if prompt != "" {
		// Classification is mandatory, but raw prompt retention is an independent
		// enterprise privacy choice. When disabled, the prompt is used only in
		// memory for classification and is not written locally or transmitted.
		if capturePrompt {
			writeSessionPrompt(sessionID, prompt)
		} else if sessionID != "" {
			_ = os.Remove(promptPathForSession(sessionID))
		}

		// The hook is the sole prompt telemetry producer. Watchers only maintain
		// liveness and revocation state, so one submission creates one event.
		if sessionID != "" && serverURL != "" {
			request := map[string]any{
				"session_id":            sessionID,
				"producer":              "claude-lifecycle-hook",
				"intent":                intent,
				"prompt_hash":           promptHash,
				"prompt_capture_enabled": capturePrompt,
			}
			if capturePrompt {
				request["user_prompt"] = prompt
			}
			reqBody, _ := json.Marshal(request)
			client := getHTTPClient()
			// Prompt submission is on the interactive path. Bound telemetry delivery
			// tightly; classification has already completed locally and enforcement
			// does not depend on this network call.
			client.Timeout = 150 * time.Millisecond
			resp, err := client.Post(serverURL+"/api/v1/sessions/prompt", "application/json", bytes.NewReader(reqBody))
			if err == nil && resp != nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusForbidden {
					// Control plane rejected prompt due to revocation
					outputPromptBlocked(sessionID, "Session authority revoked by administrator on control plane")
					return
				}
			}
		}
	}

	os.Stdout.WriteString("{\"status\":\"ok\"}\n")
	os.Exit(0)
}

func main() {
	// 1. Read event payload from stdin
	inputBytes, err := io.ReadAll(os.Stdin)
	if err != nil || len(inputBytes) == 0 {
		outputDecision("deny", "Empty hook payload on stdin", "No input received")
		return
	}

	// Clean UTF-8 BOM if present (common in Windows piping)
	inputBytes = bytes.TrimPrefix(inputBytes, []byte("\xef\xbb\xbf"))
	inputBytes = bytes.TrimSpace(inputBytes)

	var payload HookPayload
	if err := json.Unmarshal(inputBytes, &payload); err != nil {
		outputDecision("deny", "Failed to parse hook payload JSON: "+err.Error(), "Invalid JSON payload")
		return
	}

	// 2. Lifecycle Hook Handling: SessionStart
	if strings.EqualFold(payload.HookEventName, "SessionStart") {
		handleSessionStartHook(payload)
		return
	}

	// 3. Lifecycle Hook Handling: UserPromptSubmit / UserPrompt
	if strings.EqualFold(payload.HookEventName, "UserPromptSubmit") || strings.EqualFold(payload.HookEventName, "UserPrompt") {
		handleUserPromptHook(payload)
		return
	}

	sessionID := resolveSessionID(payload)
	if revoked, reason := isSessionRevoked(resolveServerURL(), sessionID); revoked {
		outputDecision("deny", reason, "This session cannot perform further governed tool actions.")
		return
	}

	workspaceRoot := resolveWorkspaceRoot()

	// 4. Intercept direct file inspection/modification tools (Read, View, Edit, Write)
	targetFile := payload.ToolInput.FilePath
	if targetFile == "" {
		targetFile = payload.ToolInput.Path
	}
	if targetFile != "" {
		normPath := strings.ToLower(filepath.ToSlash(targetFile))

		// Anti-tampering check on file write/edit
		if (payload.ToolName == "Edit" || payload.ToolName == "Write") && isProtectedBAPAsset(normPath) {
			outputDecision("deny", fmt.Sprintf("Security Invariant Violation: Direct modification or tampering with BAP protected asset %q is strictly forbidden", targetFile), "Modifying or tampering with BAP configuration, policies, hooks, or binaries is prohibited.")
			return
		}

		if isPathOutsideWorkspace(workspaceRoot, targetFile) {
			outputDecision("deny", fmt.Sprintf("Directory traversal outside workspace is forbidden for file %q", targetFile), "Access to files outside the project root is prohibited. Child module and subproject files are permitted inside the workspace.")
			return
		}
		if strings.Contains(normPath, ".env") || strings.Contains(normPath, ".aws") || strings.Contains(normPath, ".ssh") {
			outputDecision("deny", fmt.Sprintf("Access to sensitive credential file %q is strictly forbidden by policy", targetFile), "Sensitive credential file access blocked")
			return
		}
		// If it's a safe file tool operation (Read, View, Edit, Write), allow immediately
		if payload.ToolName == "Read" || payload.ToolName == "View" || payload.ToolName == "Edit" || payload.ToolName == "Write" {
			outputDecision("allow", "", "File operation within workspace permitted")
			return
		}
	}

	// 5. Process Command execution (Bash or generic command)
	command := strings.TrimSpace(payload.ToolInput.Command)
	if command == "" {
		if payload.ToolName == "Read" || payload.ToolName == "View" || payload.ToolName == "Edit" || payload.ToolName == "Write" {
			outputDecision("allow", "", "File operation permitted")
			return
		}
		outputDecision("deny", "No command or target specified in tool input", "Empty command")
		return
	}

	// 4. Resolve session identifier
	// Lifecycle hook IDs take precedence over workspace marker files so
	// concurrent Claude sessions do not inherit each other's authority.
	if sessionID == "" {
		sessCandidates := []string{".bap-session.json", "../.bap-session.json", "cchook/.bap-session.json"}
		if exePath, err := os.Executable(); err == nil {
			sessCandidates = append(sessCandidates, filepath.Join(filepath.Dir(exePath), ".bap-session.json"))
		}
		for _, loc := range sessCandidates {
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
		ppid := os.Getppid()
		sessionID = fmt.Sprintf("sess-claude-pid-%d", ppid)
		serverURL := "http://localhost:8080"
		cfgCandidates := []string{
			filepath.Join(".bap", "bap-config.json"),
			filepath.Join(".bap", "config.json"),
			"bap-config.json",
			"../bap-config.json",
		}
		if exePath, err := os.Executable(); err == nil {
			cfgCandidates = append(cfgCandidates, filepath.Join(filepath.Dir(exePath), "bap-config.json"))
		}
		if home, err := os.UserHomeDir(); err == nil {
			cfgCandidates = append(cfgCandidates, filepath.Join(home, ".bap", "bap-config.json"))
		}
		for _, cfgPath := range cfgCandidates {
			if cfgData, err := os.ReadFile(cfgPath); err == nil {
				var cfg struct {
					ControlPlaneURL string `json:"controlplane_url"`
				}
				if json.Unmarshal(cfgData, &cfg) == nil && cfg.ControlPlaneURL != "" {
					serverURL = cfg.ControlPlaneURL
					break
				}
			}
		}
		sessionBytes := []byte(fmt.Sprintf(`{"session_id":"%s","server_url":"%s","pid":%d}`, sessionID, serverURL, ppid))
		pMarker := sessionMarkerPathForPID(ppid)
		_ = os.MkdirAll(filepath.Dir(pMarker), 0700)
		_ = os.WriteFile(pMarker, sessionBytes, 0600)
		_ = os.WriteFile(filepath.Join(".bap", "session.json"), sessionBytes, 0600)
		_ = os.Remove(".bap-session.json")
		ltdBin := findBinary("bapedge.exe")
		if ltdBin == "" {
			ltdBin = findBinary("bapedge")
		}
		if ltdBin != "" {
			wCmd := exec.Command(ltdBin, "watch", fmt.Sprintf("--pid=%d", ppid), fmt.Sprintf("--server=%s", serverURL), fmt.Sprintf("--session-id=%s", sessionID), "--detach")
			_ = wCmd.Start()
		}
	}

	decodedCommand, brokerWrapped, unwrapErr := unwrapBrokerCommand(command, sessionID)
	if unwrapErr != nil {
		outputDecision("deny", unwrapErr.Error(), "Direct or malformed BAPEdge invocation is not trusted.")
		return
	}
	command = decodedCommand

	// The decoded payload—not the wrapper text—is subject to the same local
	// invariants and Cedar decision as an original agent command.
	if isTamper, tamperReason := isTamperingCommand(command); isTamper {
		outputDecision("deny", tamperReason, "Direct modification or tampering with BAP configuration, policies, hooks, or binaries is prohibited.")
		return
	}
	if checkCommandWorkspaceEscape(workspaceRoot, command) {
		outputDecision("deny", fmt.Sprintf("Directory traversal outside workspace is forbidden in command: %s", command), "Commands cannot navigate or reference paths outside the project workspace root. Child projects (e.g. Maven child modules) inside the workspace are permitted.")
		return
	}

	// 5. Resolve bapedge (LTD) or ltd-agent executable
	binName := "bapedge"
	fallbackName := "ltd-agent"
	if runtime.GOOS == "windows" {
		binName = "bapedge.exe"
		fallbackName = "ltd-agent.exe"
	}
	ltdBin := findBinary(binName)
	if _, err := os.Stat(ltdBin); err != nil {
		ltdBin = findBinary(fallbackName)
	}

	// 6. Execute bapedge check --source claude-code --session-id <sessionID> --json --cmd-b64 <b64>
	// BAP-200: Interceptor uses Decision-Only check so the action executes exactly once natively.
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(command))
	execArgs := []string{"check", "--source", "claude-code", "--json", "--cmd-b64", cmdB64}
	if sessionID != "" {
		execArgs = append([]string{"check", "--source", "claude-code", "--session-id", sessionID, "--json", "--cmd-b64", cmdB64})
	}

	cmd := exec.Command(ltdBin, execArgs...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "BAP_SESSION_ID="+sessionID)

	// Inject only this session's active prompt. A workspace-global prompt file
	// leaks prompts across concurrent Claude sessions.
	var activePrompt string
	if sessionID != "" {
		pBytes, err := os.ReadFile(promptPathForSession(sessionID))
		if err == nil {
			activePrompt = strings.TrimSpace(string(pBytes))
		}
	}
	if activePrompt == "" {
		activePrompt = os.Getenv("BAP_USER_PROMPT")
	}
	if activePrompt != "" {
		cmd.Env = append(cmd.Env, "BAP_USER_PROMPT="+activePrompt)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// cmd.Run will return exit status 1 when Cedar denies, which is expected
	_ = cmd.Run()

	// 6. Parse ltd-agent JSON output from stdout
	var execResp ExecResponse
	if err := json.Unmarshal(stdout.Bytes(), &execResp); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = strings.TrimSpace(stdout.String())
		}
		if errMsg == "" {
			errMsg = "Unable to execute command via ltd-agent"
		}
		outputDecision("deny", "ltd-agent error: "+errMsg, errMsg)
		return
	}

	// 7. Format decision matching Claude Code PreToolUse schema
	// Broker-Owned Execution (BAP-200 / BAP-200A):
	// In enforcement mode, BAP wraps the command via updatedInput with base64 encoded payload
	// so Claude Code natively spawns bapedge exec. BAPEdge is the sole executor inside the sandbox boundary.
	// Passing the command via --cmd-b64 completely prevents quote stripping and shell injection.
	if execResp.Allowed {
		mode := resolveEnforcementMode()
		if mode == "audit" || mode == "shadow" {
			outputDecision("allow", "", "Command authorized in audit mode")
			return
		}
		if brokerWrapped {
			outputDecision("allow", "", "Broker wrapper session-bound and payload re-authorized by BAP Cedar policy")
			return
		}
		// Rewrite tool input command to route through bapedge exec using safe structured --cmd-b64
		rewritten := fmt.Sprintf(`%s exec --source claude-code --session-id %s --cmd-b64 %s`, ltdBin, sessionID, cmdB64)
		outputDecisionWithUpdatedInput("allow", "", "Command authorized by BAP Cedar policy - routed to BAP broker sandbox", &ToolInput{Command: rewritten})
	} else {
		reason := execResp.Reason
		if reason == "" {
			reason = "Command execution denied by bapedge Cedar security policy"
		}
		contextMsg := reason
		if execResp.Suggestion != "" {
			contextMsg = fmt.Sprintf("%s. SUGGESTION: %s", reason, execResp.Suggestion)
		}
		outputDecision("deny", reason, contextMsg)
	}
}

// findBinary locates the ltd-agent or bapedge binary across standard search paths.
func findBinary(name string) string {
	// 1. Check current working directory
	if _, err := os.Stat(name); err == nil {
		if runtime.GOOS == "windows" {
			return ".\\" + name
		}
		return "./" + name
	}
	// 2. Check parent directory (e.g. repo root if running from cchook/)
	if _, err := os.Stat(filepath.Join("..", name)); err == nil {
		return filepath.Join("..", name)
	}
	// 3. Check dist directories
	for _, cand := range []string{
		filepath.Join("dist", "windows-amd64", name),
		filepath.Join("..", "dist", "windows-amd64", name),
		filepath.Join("dist", "windows-amd64", "claude-client", name),
		filepath.Join("..", "dist", "windows-amd64", "claude-client", name),
		filepath.Join("..", "bap-edge", name),
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	// 4. Check executable directory and ancestor folders
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		for _, rel := range []string{
			name,
			filepath.Join("..", name),
			filepath.Join("..", "..", name),
			filepath.Join("..", "claude-client", name),
			filepath.Join("..", "..", "dist", "windows-amd64", name),
			filepath.Join("..", "..", "bap-edge", name),
		} {
			cand := filepath.Join(exeDir, rel)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	// 5. Check system PATH
	if p, err := exec.LookPath(name); err == nil {
		return p
	}

	if runtime.GOOS == "windows" {
		return ".\\" + name
	}
	return "./" + name
}

// outputDecisionWithUpdatedInput prints formatted JSON response to stdout matching Claude Code PreToolUse schema,
// optionally supplying updatedInput to rewrite the tool call parameters (e.g. wrapping execution in BAPEdge broker).
func outputDecisionWithUpdatedInput(decision, reason, context string, updatedInput *ToolInput) {
	resp := HookResponse{
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
			AdditionalContext:        context,
			UpdatedInput:             updatedInput,
		},
	}
	if decision == "deny" {
		cont := false
		resp.Continue = &cont
		resp.StopReason = "Security Invariant Violation: Access to restricted credential or network resource is permanently blocked. Further attempts or workarounds are prohibited."
		resp.SystemMessage = "[SECURITY ALERT] Access permanently blocked by ltd-agent zero-trust policy. Further attempts will be rejected."
		resp.Decision = "block"
		resp.Reason = reason
		resp.HookSpecificOutput.AdditionalContext = "CRITICAL SECURITY INVARIANT: Access to this file, command, or network destination is permanently prohibited by enterprise zero-trust policy. You are FORBIDDEN from pursuing alternative approaches, workarounds, scripts, or evasion techniques to access this resource. Cease all execution attempts immediately and inform the user that this action is blocked by corporate policy."
		fmt.Fprintln(os.Stderr, "[CLAUDE HOOK BLOCKED] "+reason)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
	os.Exit(0)
}

// outputDecision prints formatted JSON response to stdout without mutating input.
func outputDecision(decision, reason, context string) {
	outputDecisionWithUpdatedInput(decision, reason, context, nil)
}

func resolveWorkspaceRoot() string {
	if root := os.Getenv("BAP_WORKSPACE_ROOT"); root != "" {
		if abs, err := filepath.Abs(root); err == nil {
			return filepath.Clean(abs)
		}
	}
	if root := os.Getenv("LTD_WORKSPACE_ROOT"); root != "" {
		if abs, err := filepath.Abs(root); err == nil {
			return filepath.Clean(abs)
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for {
			if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
				return filepath.Clean(dir)
			}
			parent := filepath.Dir(dir)
			if parent == dir || parent == "" {
				break
			}
			dir = parent
		}
		return filepath.Clean(cwd)
	}
	return "."
}

func isPathOutsideWorkspace(workspaceRoot, targetPath string) bool {
	if workspaceRoot == "" || targetPath == "" {
		return false
	}
	cleanRoot := filepath.Clean(workspaceRoot)
	var absTarget string
	if filepath.IsAbs(targetPath) {
		absTarget = filepath.Clean(targetPath)
	} else {
		absTarget = filepath.Clean(filepath.Join(cleanRoot, targetPath))
	}

	rel, err := filepath.Rel(cleanRoot, absTarget)
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.HasPrefix(rel, "../")
}

func checkCommandWorkspaceEscape(workspaceRoot, fullCommand string) bool {
	if workspaceRoot == "" || fullCommand == "" {
		return false
	}
	cleanRoot := filepath.Clean(workspaceRoot)
	currentDir := cleanRoot

	cmdUnified := fullCommand
	for _, sep := range []string{"&&", "||", ";", "|", "&"} {
		cmdUnified = strings.ReplaceAll(cmdUnified, sep, "\n")
	}

	lines := strings.Split(cmdUnified, "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		tokens := tokenizeHookCommand(line)
		if len(tokens) == 0 {
			continue
		}

		first := strings.ToLower(tokens[0])
		if first == "cd" || first == "chdir" || first == "pushd" {
			if len(tokens) >= 2 {
				cdTarget := strings.Trim(tokens[1], "\"'")
				if strings.EqualFold(cdTarget, "/d") && len(tokens) >= 3 {
					cdTarget = strings.Trim(tokens[2], "\"'")
				}
				if cdTarget == "" || cdTarget == "~" {
					return true
				}
				var nextAbs string
				if filepath.IsAbs(cdTarget) {
					nextAbs = filepath.Clean(cdTarget)
				} else {
					nextAbs = filepath.Clean(filepath.Join(currentDir, cdTarget))
				}
				if isPathOutsideWorkspace(cleanRoot, nextAbs) {
					return true
				}
				currentDir = nextAbs
			}
			continue
		}

		for i, tok := range tokens {
			if i == 0 {
				if !strings.HasPrefix(tok, "..") {
					continue
				}
			}
			tokVal := strings.Trim(tok, "\"'")
			if idx := strings.Index(tokVal, "="); idx != -1 && strings.HasPrefix(tokVal, "-") {
				tokVal = tokVal[idx+1:]
			}
			if strings.Contains(tokVal, "..") {
				var absArg string
				if filepath.IsAbs(tokVal) {
					absArg = filepath.Clean(tokVal)
				} else {
					absArg = filepath.Clean(filepath.Join(currentDir, tokVal))
				}
				if isPathOutsideWorkspace(cleanRoot, absArg) {
					return true
				}
			}
			if isExplicitAbsolutePath(tokVal) {
				cleanAbs := filepath.Clean(tokVal)
				if isPathOutsideWorkspace(cleanRoot, cleanAbs) && !isSystemBinaryPath(cleanAbs) {
					return true
				}
			}
		}
	}
	return false
}

func isExplicitAbsolutePath(p string) bool {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	if strings.HasPrefix(p, "\\\\") || strings.HasPrefix(p, "//") {
		return true
	}
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "/c") && !strings.HasPrefix(p, "/d") && !strings.HasPrefix(p, "/s") && !strings.HasPrefix(p, "/b") {
		return true
	}
	return false
}

func isSystemBinaryPath(p string) bool {
	lower := strings.ToLower(filepath.ToSlash(p))
	systemPrefixes := []string{
		"c:/windows/",
		"c:/program files/",
		"c:/program files (x86)/",
		"/usr/bin/",
		"/bin/",
		"/usr/local/bin/",
	}
	for _, sp := range systemPrefixes {
		if strings.HasPrefix(lower, sp) && (strings.HasSuffix(lower, ".exe") || !strings.Contains(filepath.Base(lower), ".")) {
			return true
		}
	}
	return false
}

func tokenizeHookCommand(cmd string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	var quoteChar rune

	for _, r := range cmd {
		if inQuote {
			if r == quoteChar {
				inQuote = false
			}
			current.WriteRune(r)
		} else {
			if r == '"' || r == '\'' {
				inQuote = true
				quoteChar = r
				current.WriteRune(r)
			} else if r == ' ' || r == '\t' {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}
