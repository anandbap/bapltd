package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"time"
)

// CallerProcessInfo captures parent process attestation details.
type CallerProcessInfo struct {
	PID        int    `json:"pid"`
	BinaryPath string `json:"binary_path"`
	BinaryName string `json:"binary_name"`
	BinaryHash string `json:"binary_hash"`
	AppID      string `json:"app_id"`
}

// UniversalHookResponse enforces the canonical contract across Claude, Codex, Copilot, etc.
type UniversalHookResponse struct {
	Status   string `json:"status"`
	Continue bool   `json:"continue"`
	Message  string `json:"message,omitempty"`
}

func emitUniversalSuccess() {
	resp := UniversalHookResponse{
		Status:   "ok",
		Continue: true,
	}
	data, _ := json.Marshal(resp)
	os.Stdout.Write(append(data, '\n'))
	os.Exit(0)
}

/*
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		procOpenProcess := kernel32.NewProc("OpenProcess")
		procCloseHandle := kernel32.NewProc("CloseHandle")
		procQueryFullProcessImageNameW := kernel32.NewProc("QueryFullProcessImageNameW")

		hProcess, _, _ := procOpenProcess.Call(0x1000, 0, uintptr(pid)) // PROCESS_QUERY_LIMITED_INFORMATION
		if hProcess == 0 {
			hProcess, _, _ = procOpenProcess.Call(0x0400, 0, uintptr(pid)) // PROCESS_QUERY_INFORMATION
		}
		if hProcess != 0 {
			defer procCloseHandle.Call(hProcess)
			var buf [1024]uint16
			size := uint32(len(buf))
			ret, _, _ := procQueryFullProcessImageNameW.Call(hProcess, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
			if ret != 0 {
				return syscall.UTF16ToString(buf[:size])
			}
		}
	} else if runtime.GOOS == "linux" {
*/
/*
			return link
		}
	}
	return ""
}

*/
func inspectCallerProcess(pid int) CallerProcessInfo {
	info := CallerProcessInfo{
		PID:   pid,
		AppID: "claude-code",
	}
	if pid <= 0 {
		return info
	}

	exePath := getProcessExecutablePath(pid)
	if exePath != "" {
		info.BinaryPath = exePath
		info.BinaryName = filepath.Base(exePath)
		if data, err := os.ReadFile(exePath); err == nil {
			h := sha256.Sum256(data)
			info.BinaryHash = fmt.Sprintf("sha256:%x", h[:])
		}

		baseLower := strings.ToLower(info.BinaryName)
		switch {
		case isClaudeApp(baseLower) || strings.Contains(baseLower, "node"):
			info.AppID = "claude-code"
		case strings.Contains(baseLower, "antigravity"):
			info.AppID = "antigravity"
		case strings.Contains(baseLower, "copilot"):
			info.AppID = "copilot"
		case strings.Contains(baseLower, "codex"):
			info.AppID = "codex"
		case strings.Contains(baseLower, "cursor"):
			info.AppID = "cursor"
		default:
			stem := strings.TrimSuffix(baseLower, filepath.Ext(baseLower))
			if stem != "" {
				info.AppID = stem
			}
		}
	}
	return info
}

// isClaudeApp checks if a process name, command, app ID, or starter script refers to Claude Code,
// Claude IDE, Claude Code CLI, Claude Code plugin, or Claude Desktop.
func isClaudeApp(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return false
	}
	if lower == "cc" {
		return true
	}
	clean := strings.ReplaceAll(lower, "-", "")
	clean = strings.ReplaceAll(clean, "_", "")
	clean = strings.ReplaceAll(clean, " ", "")
	clean = strings.ReplaceAll(clean, ".", "")
	return strings.Contains(clean, "claude")
}

// processStem lower-cases a process name and drops a trailing .exe so "bash.exe" and "bash"
// are treated alike.
func processStem(exeName string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(exeName)), ".exe")
}

func isTransientShell(exeName string) bool {
	switch processStem(exeName) {
	case "cmd", "powershell", "pwsh", "sh", "bash", "zsh", "dash", "fish", "conhost", "env", "wsl", "wslhost", "mintty":
		return true
	default:
		return false
	}
}

// isClaudeBinary matches the per-session Claude Code process (claude, claudecode, claude-code, etc.)
// Claude IDE, Claude Code CLI, Claude plugin, or starter scripts.
func isClaudeBinary(exeName string) bool {
	return isClaudeApp(processStem(exeName))
}

func isAgentBinary(exeName string) bool {
	lower := strings.ToLower(exeName)
	return isClaudeApp(lower) ||
		strings.Contains(lower, "node") ||
		strings.Contains(lower, "bun") ||
		strings.Contains(lower, "antigravity") ||
		strings.Contains(lower, "copilot") ||
		strings.Contains(lower, "codex") ||
		strings.Contains(lower, "cursor") ||
		strings.Contains(lower, "code.exe") ||
		lower == "code"
}

const maxAncestryDepth = 16

// watchPIDFor returns the PID a watcher should monitor. A shell that exits with the hook is
// never a valid target: pid 0 makes the watcher follow the session marker instead, which the
// SessionEnd hook removes.
func watchPIDFor(pid int, caller CallerProcessInfo) int {
	if isTransientShell(caller.BinaryName) {
		return 0
	}
	return pid
}

// pickAgentProcess walks up from the hook's parent and returns the process whose lifetime
// matches the agent session, never a shell that exits as soon as the hook finishes.
//
//   - Shells (cmd, pwsh, bash, sh ...) are skipped at any depth, with or without ".exe".
//   - An unreadable process name is skipped, not treated as the end of the chain.
//   - The nearest claude/claude.exe wins: it is the per-session CLI process, so the session
//     ends when it exits. The desktop app that hosts it keeps running and must not pin it.
//   - Other agents (node, bun, code, antigravity, copilot, cursor) climb to the topmost
//     contiguous agent process, since helper workers are ephemeral.
//
// If only shells are found it returns initialPID so the caller can detect that case.
func pickAgentProcess(initialPID int, parentOf func(int) int, nameOf func(int) string) int {
	topAgent := 0
	firstOwner := 0
	cur := initialPID
	for i := 0; i < maxAncestryDepth && cur > 0; i++ {
		name := nameOf(cur)
		switch {
		case name == "" || isTransientShell(name):
			// skip: unreadable or short-lived
		case isClaudeBinary(name):
			return cur
		case isAgentBinary(name):
			topAgent = cur
		default:
			if topAgent != 0 {
				return topAgent
			}
			if firstOwner == 0 {
				firstOwner = cur
			}
		}
		next := parentOf(cur)
		if next <= 0 || next == cur {
			break
		}
		cur = next
	}
	if topAgent != 0 {
		return topAgent
	}
	if firstOwner != 0 {
		return firstOwner
	}
	return initialPID
}

// resolveAgentProcess inspects caller process ancestry to pierce through transient shells,
// npm shims, and ephemeral child workers (e.g. Bun/Node helper processes spawned for hooks)
// to find the true, long-running root agent process.
func resolveAgentProcess(initialPID int) (int, CallerProcessInfo) {
	bestPID := pickAgentProcess(initialPID, getParentPID, func(pid int) string {
		if p := getProcessExecutablePath(pid); p != "" {
			return filepath.Base(p)
		}
		return ""
	})
	bestInfo := inspectCallerProcess(bestPID)

	baseLower := strings.ToLower(bestInfo.BinaryName)
	switch {
	case isClaudeApp(baseLower):
		bestInfo.AppID = "claude-code"
	case strings.Contains(baseLower, "node") || strings.Contains(baseLower, "bun"):
		if bestInfo.AppID == "" || bestInfo.AppID == "node" || bestInfo.AppID == "bun" {
			bestInfo.AppID = "claude-code"
		}
	case strings.Contains(baseLower, "antigravity"):
		bestInfo.AppID = "antigravity"
	case strings.Contains(baseLower, "copilot"):
		bestInfo.AppID = "copilot"
	case strings.Contains(baseLower, "codex"):
		bestInfo.AppID = "codex"
	case strings.Contains(baseLower, "cursor"):
		bestInfo.AppID = "cursor"
	default:
		if bestInfo.AppID == "" || isTransientShell(bestInfo.BinaryName) {
			bestInfo.AppID = "claude-code"
		}
	}

	// Recognize starter scripts, Claude IDE, Claude plugin, or explicit LTD_SOURCE / BAP_SOURCE
	if isClaudeApp(os.Getenv("LTD_SOURCE")) || isClaudeApp(os.Getenv("BAP_SOURCE")) ||
		isClaudeApp(os.Getenv("CLAUDE_CODE_ENTRYPOINT")) || os.Getenv("CLAUDE_IDE") != "" ||
		os.Getenv("CLAUDE_PLUGIN") != "" {
		bestInfo.AppID = "claude-code"
	}

	return bestPID, bestInfo
}

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

// shouldCaptureAgentResponse mirrors shouldCaptureUserPrompt: raw agent output retention is an
// independent privacy choice that defaults to following the prompt-capture setting.
func shouldCaptureAgentResponse() bool {
	if value := strings.TrimSpace(os.Getenv("BAP_CAPTURE_AGENT_RESPONSE")); value != "" {
		if enabled, err := strconv.ParseBool(value); err == nil {
			return enabled
		}
	}
	for _, cfgPath := range []string{filepath.Join(".bap", "bap-config.json"), filepath.Join(".bap", "config.json"), "bap-config.json", "../bap-config.json"} {
		if cfgData, err := os.ReadFile(cfgPath); err == nil {
			var cfg struct {
				CaptureAgentResponse *bool `json:"capture_agent_response"`
			}
			if json.Unmarshal(cfgData, &cfg) == nil && cfg.CaptureAgentResponse != nil {
				return *cfg.CaptureAgentResponse
			}
		}
	}
	return shouldCaptureUserPrompt()
}

// lastAssistantText returns the assistant text produced since the most recent user prompt in a
// Claude Code JSONL transcript. Tool-result turns are not prompts, so they do not reset it.
func lastAssistantText(transcriptPath string) string {
	data, err := os.ReadFile(transcriptPath)
	if err != nil {
		return ""
	}
	var parts []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry struct {
			Type    string `json:"type"`
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		switch entry.Type {
		case "user":
			var asString string
			if json.Unmarshal(entry.Message.Content, &asString) == nil {
				parts = nil
			} else if json.Unmarshal(entry.Message.Content, &blocks) == nil {
				for _, b := range blocks {
					if b.Type == "text" {
						parts = nil
					}
				}
			}
		case "assistant":
			if json.Unmarshal(entry.Message.Content, &blocks) == nil {
				for _, b := range blocks {
					if b.Type == "text" && strings.TrimSpace(b.Text) != "" {
						parts = append(parts, b.Text)
					}
				}
			}
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n\n"))
}

// allUserPrompts extracts all unique user prompts from an Antigravity or Claude JSONL transcript in chronological order.
func allUserPrompts(transcriptPath, conversationID string) []string {
	if transcriptPath == "" && conversationID != "" {
		homeDir, _ := os.UserHomeDir()
		cand := filepath.Join(homeDir, ".gemini", "antigravity", "brain", conversationID, ".system_generated", "logs", "transcript.jsonl")
		if _, err := os.Stat(cand); err == nil {
			transcriptPath = cand
		}
	}
	if transcriptPath == "" {
		return nil
	}
	data, err := os.ReadFile(transcriptPath)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	var prompts []string
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		var entry struct {
			Type    string `json:"type"`
			Source  string `json:"source"`
			Content string `json:"content"`
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		var text string
		// Antigravity format
		if entry.Type == "USER_INPUT" || entry.Source == "USER_EXPLICIT" {
			text = entry.Content
			if start := strings.Index(text, "<USER_REQUEST>"); start != -1 {
				start += len("<USER_REQUEST>")
				if end := strings.Index(text[start:], "</USER_REQUEST>"); end != -1 {
					text = text[start : start+end]
				} else {
					text = text[start:]
				}
			}
			text = strings.TrimSpace(text)
		} else if entry.Type == "user" {
			// Claude Code format
			var asString string
			if json.Unmarshal(entry.Message.Content, &asString) == nil && asString != "" {
				text = strings.TrimSpace(asString)
			} else {
				var blocks []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}
				if json.Unmarshal(entry.Message.Content, &blocks) == nil {
					for _, b := range blocks {
						if b.Type == "text" && strings.TrimSpace(b.Text) != "" {
							text = strings.TrimSpace(b.Text)
							break
						}
					}
				}
			}
		}
		if text != "" {
			if len(prompts) == 0 || prompts[len(prompts)-1] != text {
				prompts = append(prompts, text)
			}
		}
	}
	return prompts
}

// lastUserPromptText extracts the most recent user prompt from an Antigravity or Claude JSONL transcript.
func lastUserPromptText(transcriptPath, conversationID string) string {
	if transcriptPath == "" && conversationID != "" {
		homeDir, _ := os.UserHomeDir()
		cand := filepath.Join(homeDir, ".gemini", "antigravity", "brain", conversationID, ".system_generated", "logs", "transcript.jsonl")
		if _, err := os.Stat(cand); err == nil {
			transcriptPath = cand
		}
	}
	if transcriptPath == "" {
		return ""
	}
	data, err := os.ReadFile(transcriptPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var entry struct {
			Type    string `json:"type"`
			Source  string `json:"source"`
			Content string `json:"content"`
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		// Antigravity format
		if entry.Type == "USER_INPUT" || entry.Source == "USER_EXPLICIT" {
			text := entry.Content
			if start := strings.Index(text, "<USER_REQUEST>"); start != -1 {
				start += len("<USER_REQUEST>")
				if end := strings.Index(text[start:], "</USER_REQUEST>"); end != -1 {
					text = text[start : start+end]
				} else {
					text = text[start:]
				}
			}
			text = strings.TrimSpace(text)
			if text != "" {
				return text
			}
		}
		// Claude Code format
		if entry.Type == "user" {
			var asString string
			if json.Unmarshal(entry.Message.Content, &asString) == nil && asString != "" {
				return strings.TrimSpace(asString)
			}
			var blocks []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			if json.Unmarshal(entry.Message.Content, &blocks) == nil {
				for _, b := range blocks {
					if b.Type == "text" && strings.TrimSpace(b.Text) != "" {
						return strings.TrimSpace(b.Text)
					}
				}
			}
		}
	}
	return ""
}

// handleStopHook reports the agent's finished reply so the dashboard can show it next to the
// prompt. It is telemetry only: it never blocks the agent from stopping.
func handleStopHook(payload HookPayload) {
	defer func() {
		os.Stdout.WriteString("{}\n")
		os.Exit(0)
	}()
	if !shouldCaptureAgentResponse() {
		return
	}
	response := strings.TrimSpace(payload.LastAssistantMessage)
	if response == "" && payload.TranscriptPath != "" {
		response = lastAssistantText(payload.TranscriptPath)
	}
	if response == "" {
		return
	}
	serverURL := resolveServerURL()
	sessionID := resolveSessionID(payload)
	if sessionID == "" {
		targetPID, caller := resolveAgentProcess(os.Getppid())
		sessionID = fmt.Sprintf("sess-%s-pid-%d", caller.AppID, targetPID)
	}
	if serverURL == "" {
		return
	}
	digest := sha256.Sum256([]byte(sessionID + "\x00" + response))
	reqBody, _ := json.Marshal(map[string]any{
		"session_id":     sessionID,
		"producer":       "claude-lifecycle-hook",
		"agent_response": response,
		"response_hash":  fmt.Sprintf("%x", digest[:]),
	})
	client := getHTTPClient()
	client.Timeout = 2 * time.Second
	resp, err := client.Post(serverURL+"/api/v1/sessions/response", "application/json", bytes.NewReader(reqBody))
	if err != nil || resp == nil {
		hookLog("response delivery failed (session %s): %v", sessionID, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		hookLog("response POST returned HTTP %d (session %s)", resp.StatusCode, sessionID)
	}
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

//go:embed certs
var certsFS embed.FS

func getHTTPClient() *http.Client {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caData, err := certsFS.ReadFile("certs/embedded_ca.crt"); err == nil && len(caData) > 0 {
		roots.AppendCertsFromPEM(caData)
	}
	if pemStr := os.Getenv("BAP_CA_CERT_PEM"); pemStr != "" {
		roots.AppendCertsFromPEM([]byte(pemStr))
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
		Timeout:   10 * time.Second,
		Transport: tr,
	}
}

// ToolInput represents the input object from Claude Code.
// Supports both command-execution (Bash) and direct file tools (Read, View, Edit, Write).
type ToolInput struct {
	Command       string `json:"command,omitempty"`
	Cmd           string `json:"cmd,omitempty"`
	CommandLine   string `json:"CommandLine,omitempty"`
	Script        string `json:"script,omitempty"`
	FilePath      string `json:"file_path,omitempty"`
	FilePathCamel string `json:"filePath,omitempty"`
	Path          string `json:"path,omitempty"`
	File          string `json:"file,omitempty"`
	Target        string `json:"target,omitempty"`
	TargetPath    string `json:"targetPath,omitempty"`
}

// AntigravityToolCall represents toolCall structure in Antigravity hook payloads.
type AntigravityToolCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args,omitempty"`
}

// HookPayload represents the Claude Code, Antigravity, Codex, Copilot, and generic lifecycle event payload.
type HookPayload struct {
	HookEventName      string                 `json:"hook_event_name"`
	EventName          string                 `json:"event_name,omitempty"`
	Event              string                 `json:"event,omitempty"`
	Type               string                 `json:"type,omitempty"`
	ToolName           string                 `json:"tool_name,omitempty"`
	ToolNameCamel      string                 `json:"toolName,omitempty"`
	Tool               string                 `json:"tool,omitempty"`
	Name               string                 `json:"name,omitempty"`
	ToolInput          ToolInput              `json:"tool_input,omitempty"`
	ToolInputCamel     *ToolInput             `json:"toolInput,omitempty"`
	Input              *ToolInput             `json:"input,omitempty"`
	Args               map[string]interface{} `json:"args,omitempty"`
	Arguments          map[string]interface{} `json:"arguments,omitempty"`
	Parameters         map[string]interface{} `json:"parameters,omitempty"`
	UserPrompt         string                 `json:"user_prompt,omitempty"`
	UserPromptCamel    string                 `json:"userPrompt,omitempty"`
	Prompt             string                 `json:"prompt,omitempty"`
	SessionID          string                 `json:"session_id,omitempty"`
	SessionIDCamel     string                 `json:"sessionId,omitempty"`
	Session            string                 `json:"session,omitempty"`
	DecisionStyle      string                 `json:"decision_style,omitempty"`
	DecisionStyleCamel string                 `json:"decisionStyle,omitempty"`
	Format             string                 `json:"format,omitempty"`
	Source             string                 `json:"source,omitempty"`
	AppID              string                 `json:"app_id,omitempty"`
	AppIDCamel         string                 `json:"appId,omitempty"`

	// Antigravity lifecycle fields (supports both camelCase and snake_case)
	ConversationID      string               `json:"conversationId,omitempty"`
	TranscriptPath      string               `json:"transcriptPath,omitempty"`
	TranscriptPathSnake string               `json:"transcript_path,omitempty"`
	ToolCall            *AntigravityToolCall `json:"toolCall,omitempty"`

	// Stop hook fields.
	LastAssistantMessage string `json:"last_assistant_message,omitempty"`
}

// HookSpecificOutput represents the PreToolUse decision schema.
type HookSpecificOutput struct {
	HookEventName            string     `json:"hookEventName"`
	PermissionDecision       string     `json:"permissionDecision"` // "allow" or "deny"
	PermissionDecisionReason string     `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string     `json:"additionalContext,omitempty"`
	UpdatedInput             *ToolInput `json:"updatedInput,omitempty"`
}

// HookResponse is the top-level response expected by Claude Code, Codex, Antigravity, and generic tool runners.
type HookResponse struct {
	Status             string             `json:"status,omitempty"`             // "ok", "blocked" (UniversalHookResponse)
	Continue           *bool              `json:"continue,omitempty"`           // true / false (Codex / universal)
	StopReason         string             `json:"stopReason,omitempty"`         // Claude Code
	SystemMessage      string             `json:"systemMessage,omitempty"`      // Claude Code
	Decision           string             `json:"decision,omitempty"`           // "approve" | "block" for Claude; "allow" | "deny" for generic tools
	Allowed            *bool              `json:"allowed,omitempty"`            // Universal boolean: true / false
	PermissionDecision string             `json:"permissionDecision,omitempty"` // Direct flat alias: "allow" / "deny"
	Reason             string             `json:"reason,omitempty"`
	UpdatedInput       *ToolInput         `json:"updatedInput,omitempty"`       // Direct flat alias for generic runners
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

var (
	activeDecisionStyle string
	activeCallerAppID   string
)

// normalizeHookPayload ensures all tool runner variants (Claude Code, Antigravity, Copilot, Codex, etc.)
// map cleanly to normalized fields regardless of casing or schema differences.
func normalizeHookPayload(payload *HookPayload) {
	if payload == nil {
		return
	}
	// Normalize HookEventName
	if payload.HookEventName == "" {
		if payload.EventName != "" {
			payload.HookEventName = payload.EventName
		} else if payload.Event != "" {
			payload.HookEventName = payload.Event
		} else if payload.Type != "" {
			payload.HookEventName = payload.Type
		}
	}
	// Normalize ToolName
	if payload.ToolName == "" {
		if payload.ToolNameCamel != "" {
			payload.ToolName = payload.ToolNameCamel
		} else if payload.Tool != "" {
			payload.ToolName = payload.Tool
		} else if payload.Name != "" {
			payload.ToolName = payload.Name
		}
	}
	// Normalize ToolInput Command
	if payload.ToolInput.Command == "" {
		if payload.ToolInput.Cmd != "" {
			payload.ToolInput.Command = payload.ToolInput.Cmd
		} else if payload.ToolInput.CommandLine != "" {
			payload.ToolInput.Command = payload.ToolInput.CommandLine
		} else if payload.ToolInput.Script != "" {
			payload.ToolInput.Command = payload.ToolInput.Script
		} else if payload.ToolInputCamel != nil && payload.ToolInputCamel.Command != "" {
			payload.ToolInput = *payload.ToolInputCamel
		} else if payload.Input != nil && payload.Input.Command != "" {
			payload.ToolInput = *payload.Input
		} else if payload.Args != nil {
			if c, ok := payload.Args["command"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			} else if c, ok := payload.Args["CommandLine"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			} else if c, ok := payload.Args["cmd"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			}
		} else if payload.Arguments != nil {
			if c, ok := payload.Arguments["command"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			} else if c, ok := payload.Arguments["CommandLine"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			} else if c, ok := payload.Arguments["cmd"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			}
		} else if payload.Parameters != nil {
			if c, ok := payload.Parameters["command"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			} else if c, ok := payload.Parameters["CommandLine"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			} else if c, ok := payload.Parameters["cmd"].(string); ok && c != "" {
				payload.ToolInput.Command = c
			}
		}
	}
	// Normalize ToolInput FilePath
	if payload.ToolInput.FilePath == "" {
		if payload.ToolInput.FilePathCamel != "" {
			payload.ToolInput.FilePath = payload.ToolInput.FilePathCamel
		} else if payload.ToolInput.Path != "" {
			payload.ToolInput.FilePath = payload.ToolInput.Path
		} else if payload.ToolInput.File != "" {
			payload.ToolInput.FilePath = payload.ToolInput.File
		} else if payload.ToolInput.Target != "" {
			payload.ToolInput.FilePath = payload.ToolInput.Target
		} else if payload.ToolInput.TargetPath != "" {
			payload.ToolInput.FilePath = payload.ToolInput.TargetPath
		} else if payload.Args != nil {
			if f, ok := payload.Args["file_path"].(string); ok && f != "" {
				payload.ToolInput.FilePath = f
			} else if f, ok := payload.Args["filePath"].(string); ok && f != "" {
				payload.ToolInput.FilePath = f
			} else if f, ok := payload.Args["path"].(string); ok && f != "" {
				payload.ToolInput.FilePath = f
			}
		}
	}
	// Normalize SessionID
	if payload.SessionID == "" {
		if payload.SessionIDCamel != "" {
			payload.SessionID = payload.SessionIDCamel
		} else if payload.Session != "" {
			payload.SessionID = payload.Session
		} else if payload.ConversationID != "" {
			payload.SessionID = payload.ConversationID
		}
	}
	// Normalize UserPrompt
	if payload.UserPrompt == "" {
		if payload.UserPromptCamel != "" {
			payload.UserPrompt = payload.UserPromptCamel
		} else if payload.Prompt != "" {
			payload.UserPrompt = payload.Prompt
		}
	}
	// Normalize DecisionStyle / Format
	if payload.DecisionStyle == "" {
		if payload.DecisionStyleCamel != "" {
			payload.DecisionStyle = payload.DecisionStyleCamel
		} else if payload.Format != "" {
			payload.DecisionStyle = payload.Format
		}
	}
	// Normalize AppID
	if payload.AppID == "" {
		if payload.AppIDCamel != "" {
			payload.AppID = payload.AppIDCamel
		} else if payload.Source != "" {
			payload.AppID = payload.Source
		} else if payload.ToolCall != nil || payload.ConversationID != "" {
			payload.AppID = "antigravity"
		}
	}
	if isClaudeApp(payload.AppID) {
		payload.AppID = "claude-code"
	}
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
	// Direct agent invocation via bapedge exec "<command>" as instructed by AGENTS.md / GEMINI.md
	if len(fields) >= 2 && fields[1] == "exec" && !strings.Contains(command, "--cmd-b64") {
		idx := strings.Index(command, "exec")
		rawInner := strings.TrimSpace(command[idx+4:])
		rawInner = strings.Trim(rawInner, `"'`)
		if rawInner != "" {
			return rawInner, false, nil
		}
	}
	validSource := len(fields) > 3 && (isClaudeApp(fields[3]) || fields[3] == "copilot" || fields[3] == "antigravity" || fields[3] == "codex" || fields[3] == "cursor")
	if len(fields) != 8 || fields[1] != "exec" || fields[2] != "--source" || !validSource || fields[4] != "--session-id" || fields[6] != "--cmd-b64" {
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
	if s := os.Getenv("BAP_CONTROL_PLANE_URL"); s != "" {
		return strings.TrimRight(s, "/")
	}
	if s := os.Getenv("LTD_SERVER_URL"); s != "" {
		return strings.TrimRight(s, "/")
	}

	cfgCandidates := []string{
		"bap-config.json",
		filepath.Join(".bap", "config.json"),
		filepath.Join(".bap", "bap-config.json"),
		"../bap-config.json",
		"../../bap-config.json",
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		cfgCandidates = append(cfgCandidates, filepath.Join(exeDir, "bap-config.json"))
		cfgCandidates = append(cfgCandidates, filepath.Join(exeDir, "..", "bap-config.json"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		cfgCandidates = append(cfgCandidates, filepath.Join(home, ".bap", "config.json"))
		cfgCandidates = append(cfgCandidates, filepath.Join(home, ".bap", "bap-config.json"))
		cfgCandidates = append(cfgCandidates, filepath.Join(home, ".bapstate", "credentials.json"))
		cfgCandidates = append(cfgCandidates, filepath.Join(home, ".bapstate", "config.json"))
	}

	for _, cfgPath := range cfgCandidates {
		if cfgData, err := os.ReadFile(cfgPath); err == nil {
			var raw map[string]interface{}
			if json.Unmarshal(cfgData, &raw) == nil {
				for _, key := range []string{"controlplane_url", "control_plane_url", "server_url", "server"} {
					if val, ok := raw[key].(string); ok && strings.TrimSpace(val) != "" {
						return strings.TrimRight(strings.TrimSpace(val), "/")
					}
				}
			}
		}
	}
	return "http://localhost:8080"
}

func resolveEnforcementMode() string {
	if m := os.Getenv("BAP_ENFORCEMENT_MODE"); m != "" {
		return strings.ToLower(strings.TrimSpace(m))
	}
	if m := os.Getenv("BAP_MODE"); m != "" {
		return strings.ToLower(strings.TrimSpace(m))
	}
	var cfgCandidates []string
	cfgCandidates = append(cfgCandidates,
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
		"../bap-config.json",
	)
	home, _ := os.UserHomeDir()
	if home != "" {
		cfgCandidates = append(cfgCandidates,
			filepath.Join(home, ".bapstate", "config.json"),
			filepath.Join(home, "bin", "bap-config.json"),
			filepath.Join(home, ".bap", "config.json"),
			filepath.Join(home, ".bap", "bap-config.json"),
		)
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

func isSessionTrustGranted(sessionID, fullCommand, executable string) bool {
	if sessionID == "" {
		return false
	}
	safeID := strings.ReplaceAll(sessionID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	safeID = strings.ReplaceAll(safeID, "\\", "_")
	path := filepath.Join(".bap", fmt.Sprintf("approvals_%s.json", safeID))
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var rec struct {
		ApprovedCommands    map[string]string `json:"approved_commands"`
		ApprovedExecutables map[string]bool   `json:"approved_executables"`
	}
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

type PathPermission struct {
	Path      string    `json:"path"`
	Actions   []string  `json:"actions"`
	Scope     string    `json:"scope"`
	GrantedAt time.Time `json:"granted_at,omitempty"`
	GrantedBy string    `json:"granted_by,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
}

type PermissionsStore struct {
	TrustedPaths []PathPermission `json:"trusted_paths"`
}

func isTargetAuthorized(workspaceRoot, sessionID, targetPath, action string) (bool, string) {
	if targetPath == "" {
		return false, ""
	}
	cleanTarget := filepath.Clean(targetPath)
	if abs, err := filepath.Abs(cleanTarget); err == nil {
		cleanTarget = abs
	}
	normAction := strings.ToLower(strings.TrimSpace(action))
	if normAction == "" {
		normAction = "write"
	}

	checkFile := func(filePath, scope string) bool {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return false
		}
		var store PermissionsStore
		if json.Unmarshal(data, &store) == nil && len(store.TrustedPaths) > 0 {
			for _, p := range store.TrustedPaths {
				if isPathCovered(p.Path, cleanTarget) && actionMatches(p.Actions, normAction) {
					return true
				}
			}
		}
		var legacy struct {
			ApprovedPaths []PathPermission `json:"approved_paths"`
		}
		if json.Unmarshal(data, &legacy) == nil && len(legacy.ApprovedPaths) > 0 {
			for _, p := range legacy.ApprovedPaths {
				if isPathCovered(p.Path, cleanTarget) && actionMatches(p.Actions, normAction) {
					return true
				}
			}
		}
		return false
	}

	// 1. Session scope
	if sessionID != "" {
		safeID := strings.ReplaceAll(sessionID, ":", "_")
		safeID = strings.ReplaceAll(safeID, "/", "_")
		safeID = strings.ReplaceAll(safeID, "\\", "_")
		sessPath := filepath.Join(workspaceRoot, ".bap", fmt.Sprintf("approvals_%s.json", safeID))
		if checkFile(sessPath, "session") {
			return true, "session"
		}
	}

	// 2. Project scope
	projPath := filepath.Join(workspaceRoot, ".bap", "project_permissions.json")
	if checkFile(projPath, "project") {
		return true, "project"
	}

	// 3. Global scope
	if home, err := os.UserHomeDir(); err == nil {
		globPath := filepath.Join(home, ".bap", "global_permissions.json")
		if checkFile(globPath, "global") {
			return true, "global"
		}
	}

	return false, ""
}

func grantTargetPermission(workspaceRoot, sessionID, targetPath, scope string, actions []string) error {
	if targetPath == "" {
		return nil
	}
	cleanPath, err := filepath.Abs(targetPath)
	if err != nil {
		cleanPath = filepath.Clean(targetPath)
	}
	if len(actions) == 0 {
		actions = []string{"write", "delete"}
	}
	perm := PathPermission{
		Path:      cleanPath,
		Actions:   actions,
		Scope:     scope,
		GrantedAt: time.Now().UTC(),
		GrantedBy: "user_override",
		SessionID: sessionID,
	}

	var filePath string
	switch strings.ToLower(scope) {
	case "session":
		safeID := strings.ReplaceAll(sessionID, ":", "_")
		safeID = strings.ReplaceAll(safeID, "/", "_")
		safeID = strings.ReplaceAll(safeID, "\\", "_")
		filePath = filepath.Join(workspaceRoot, ".bap", fmt.Sprintf("approvals_%s.json", safeID))
	case "project":
		filePath = filepath.Join(workspaceRoot, ".bap", "project_permissions.json")
	case "global":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		filePath = filepath.Join(home, ".bap", "global_permissions.json")
	default:
		return fmt.Errorf("invalid scope: %s", scope)
	}

	_ = os.MkdirAll(filepath.Dir(filePath), 0700)
	var existing []PathPermission
	if data, err := os.ReadFile(filePath); err == nil {
		var store PermissionsStore
		if json.Unmarshal(data, &store) == nil {
			existing = store.TrustedPaths
		}
	}
	updated := false
	for i, p := range existing {
		if strings.EqualFold(filepath.Clean(p.Path), cleanPath) {
			existing[i] = perm
			updated = true
			break
		}
	}
	if !updated {
		existing = append(existing, perm)
	}
	b, err := json.MarshalIndent(PermissionsStore{TrustedPaths: existing}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, b, 0600)
}

func isPathCovered(trustedPath, targetPath string) bool {
	if trustedPath == "" || targetPath == "" {
		return false
	}
	cleanTrusted := filepath.Clean(trustedPath)
	cleanTarget := filepath.Clean(targetPath)
	if abs, err := filepath.Abs(cleanTrusted); err == nil {
		cleanTrusted = abs
	}
	if abs, err := filepath.Abs(cleanTarget); err == nil {
		cleanTarget = abs
	}

	if strings.EqualFold(cleanTrusted, cleanTarget) {
		return true
	}
	rel, err := filepath.Rel(cleanTrusted, cleanTarget)
	if err != nil {
		return false
	}
	if rel == "." || (!strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, "/") && !strings.HasPrefix(rel, "\\")) {
		return true
	}
	return false
}

func actionMatches(actions []string, requested string) bool {
	if len(actions) == 0 {
		return true
	}
	for _, a := range actions {
		lower := strings.ToLower(strings.TrimSpace(a))
		if lower == "all" || lower == "*" || lower == requested {
			return true
		}
		if (requested == "write" || requested == "delete") && lower == "modify" {
			return true
		}
	}
	return false
}

func isMutatingShellCommand(cmd string) bool {
	lower := strings.ToLower(cmd)
	if strings.Contains(lower, ">") {
		return true
	}
	destructive := []string{
		"rm ", "rm -", "del ", "erase ", "remove-item", "unlink", "rmdir", "rd /", "rd ",
		"mkdir ", "md ", "touch ", "cp ", "copy ", "mv ", "move ", "ren ", "rename ",
		"set-content", "out-file", "add-content",
	}
	for _, d := range destructive {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

func extractCommandTarget(cmd string) string {
	if parts := strings.Split(cmd, ">"); len(parts) > 1 {
		return strings.TrimSpace(strings.Trim(parts[len(parts)-1], "\"'`"))
	}
	tokens := tokenizeHookCommand(cmd)
	for i := 1; i < len(tokens); i++ {
		t := strings.Trim(tokens[i], "\"'`")
		if !strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "/") && len(t) > 1 {
			return t
		}
	}
	return ""
}

func isSafeFileTool(toolLower string) bool {
	return toolLower == "read" || toolLower == "view" || toolLower == "edit" || toolLower == "write" ||
		toolLower == "read_file" || toolLower == "view_file" || toolLower == "write_file" ||
		toolLower == "edit_file" || toolLower == "replace_file_content" ||
		toolLower == "show_file" || toolLower == "get_file" || toolLower == "create_file" ||
		toolLower == "delete_file" || toolLower == "patch" || toolLower == "str_replace_editor"
}

func isSafeSubagentOrInspectionTool(toolLower string) bool {
	if strings.Contains(toolLower, "search") || strings.Contains(toolLower, "subagent") ||
		strings.Contains(toolLower, "agent") || strings.Contains(toolLower, "task") ||
		strings.Contains(toolLower, "grep") || strings.Contains(toolLower, "glob") ||
		strings.Contains(toolLower, "list") || strings.Contains(toolLower, "find") ||
		toolLower == "ls" || toolLower == "dir" || strings.HasPrefix(toolLower, "bap_") {
		return true
	}
	return false
}

func isShellTool(toolLower string) bool {
	return toolLower == "bash" || toolLower == "sh" || toolLower == "terminal" ||
		toolLower == "command" || toolLower == "execute" || toolLower == "run_command" ||
		toolLower == "shell" || toolLower == "powershell" || toolLower == "pwsh" ||
		toolLower == "cmd" || strings.Contains(toolLower, "shell") ||
		strings.Contains(toolLower, "terminal") || strings.Contains(toolLower, "command") ||
		strings.HasPrefix(toolLower, "exec") || strings.HasPrefix(toolLower, "run_") ||
		toolLower == ""
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

const maxDevOverrideWindow = 12 * time.Hour

// resolveEnvironment returns the deployment environment from BAP_ENVIRONMENT or the first config
// that declares one. An unknown environment is treated as production.
func resolveEnvironment() string {
	if e := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_ENVIRONMENT"))); e != "" {
		return e
	}
	cfgCandidates := []string{filepath.Join(".bap", "bap-config.json"), filepath.Join(".bap", "config.json"), "bap-config.json", "../bap-config.json"}
	if home, _ := os.UserHomeDir(); home != "" {
		cfgCandidates = append(cfgCandidates,
			filepath.Join(home, ".bapstate", "config.json"),
			filepath.Join(home, ".bap", "config.json"),
			filepath.Join(home, ".bap", "bap-config.json"))
	}
	for _, p := range cfgCandidates {
		if data, err := os.ReadFile(p); err == nil {
			var cfg struct {
				Environment string `json:"environment"`
			}
			if json.Unmarshal(data, &cfg) == nil && cfg.Environment != "" {
				return strings.ToLower(strings.TrimSpace(cfg.Environment))
			}
		}
	}
	return "production"
}

func resolveConfiguredAdminToken() string {
	if t := strings.TrimSpace(os.Getenv("BAP_CISO_TOKEN")); t != "" {
		return t
	}
	cfgCandidates := []string{
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
	}
	if home, _ := os.UserHomeDir(); home != "" {
		cfgCandidates = append(cfgCandidates,
			filepath.Join(home, ".bapstate", "config.json"),
			filepath.Join(home, ".bap", "config.json"),
		)
	}
	for _, p := range cfgCandidates {
		if data, err := os.ReadFile(p); err == nil {
			var cfg struct {
				AdminToken       string `json:"admin_token"`
				CISOToken        string `json:"ciso_token"`
				DevOverrideToken string `json:"dev_override_token"`
			}
			if json.Unmarshal(data, &cfg) == nil {
				if cfg.AdminToken != "" {
					return cfg.AdminToken
				}
				if cfg.CISOToken != "" {
					return cfg.CISOToken
				}
				if cfg.DevOverrideToken != "" {
					return cfg.DevOverrideToken
				}
			}
		}
	}
	return ""
}

func computeOverrideSignature(active bool, activatedAt, expiresAt int64, authorizedBy, authMethod, secret string) string {
	payload := fmt.Sprintf("%v|%d|%d|%s|%s", active, activatedAt, expiresAt, authorizedBy, authMethod)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func parseDevOverrideExpiry(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	lower := strings.ToLower(raw)
	if lower == "1" || lower == "true" || lower == "on" || lower == "yes" || lower == "active" {
		return time.Now().Add(maxDevOverrideWindow), true
	}
	if dur, err := time.ParseDuration(raw); err == nil && dur > 0 {
		if dur > maxDevOverrideWindow {
			dur = maxDevOverrideWindow
		}
		return time.Now().Add(dur), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// AllowDevOverrides controls whether developer override features are permitted.
// Injected at compile-time via -ldflags "-X 'main.AllowDevOverrides=false'".
var AllowDevOverrides = "true"

// devOverrideActive reports whether the human operator has opened a time-boxed development
// window. It relaxes only the anti-tampering rules on BAP's own files and binaries so BAP itself
// can be developed under BAP. Credential protection, revocation and Cedar policy stay in force.
func devOverrideActive() (bool, string) {
	if !strings.EqualFold(strings.TrimSpace(AllowDevOverrides), "true") {
		return false, ""
	}
	configuredAdmin := resolveConfiguredAdminToken()

	// 1. Check environment variable BAP_DEV_OVERRIDE or BAP_DEV_MODE
	raw := strings.TrimSpace(os.Getenv("BAP_DEV_OVERRIDE"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("BAP_DEV_MODE"))
	}
	if raw != "" {
		if configuredAdmin != "" {
			providedToken := strings.TrimSpace(os.Getenv("BAP_ADMIN_TOKEN"))
			if providedToken == "" {
				providedToken = raw
			}
			if subtle.ConstantTimeCompare([]byte(providedToken), []byte(configuredAdmin)) != 1 {
				return false, ""
			}
		}
		if until, ok := parseDevOverrideExpiry(raw); ok {
			now := time.Now()
			if until.After(now) {
				return true, fmt.Sprintf("[BAP DEV OVERRIDE ACTIVE until %s] Anti-tampering checks on BAP files are suspended; credentials, revocation and policy still apply.", until.Format(time.RFC3339))
			}
		}
	}

	// 2. Check marker file: .bap/dev-override.json or ~/.bapstate/dev-override.json
	markerCandidates := []string{
		filepath.Join(".bap", "dev-override.json"),
		"dev-override.json",
	}
	if home, _ := os.UserHomeDir(); home != "" {
		markerCandidates = append(markerCandidates, filepath.Join(home, ".bapstate", "dev-override.json"))
	}
	for _, m := range markerCandidates {
		if data, err := os.ReadFile(m); err == nil {
			var d struct {
				Active       bool      `json:"active"`
				ActivatedAt  time.Time `json:"activated_at"`
				ExpiresAt    time.Time `json:"expires_at"`
				AuthorizedBy string    `json:"authorized_by"`
				AuthMethod   string    `json:"auth_method"`
				Signature    string    `json:"signature,omitempty"`
			}
			if json.Unmarshal(data, &d) == nil && d.Active {
				if configuredAdmin != "" && d.Signature != "" {
					expectedSig := computeOverrideSignature(d.Active, d.ActivatedAt.Unix(), d.ExpiresAt.Unix(), d.AuthorizedBy, d.AuthMethod, configuredAdmin)
					if subtle.ConstantTimeCompare([]byte(d.Signature), []byte(expectedSig)) != 1 {
						continue
					}
				}
				if d.ExpiresAt.After(time.Now()) {
					return true, fmt.Sprintf("[BAP DEV OVERRIDE ACTIVE until %s (Auth: %s)] Anti-tampering checks on BAP files are suspended; credentials, revocation and policy still apply.", d.ExpiresAt.Format(time.RFC3339), d.AuthMethod)
				}
			}
		}
	}

	// 3. Check bap-config.json
	cfgCandidates := []string{
		filepath.Join(".bap", "bap-config.json"),
		filepath.Join(".bap", "config.json"),
		"bap-config.json",
	}
	for _, p := range cfgCandidates {
		if data, err := os.ReadFile(p); err == nil {
			var cfg struct {
				DevOverride bool `json:"dev_override"`
			}
			if json.Unmarshal(data, &cfg) == nil && cfg.DevOverride {
				if configuredAdmin == "" {
					return true, "[BAP DEV OVERRIDE ACTIVE via config] Anti-tampering checks on BAP files are suspended; credentials, revocation and policy still apply."
				}
			}
		}
	}

	return false, ""
}

func stripHeredocs(cmdStr string) string {
	lines := strings.Split(cmdStr, "\n")
	var result []string
	var heredocDelim string
	inHeredoc := false
	isStripTabs := false

	heredocRe := regexp.MustCompile(`<<(-)?\s*(?:'([^']+)'|"([^"]+)"|\\?([a-zA-Z0-9_]+))`)

	for _, line := range lines {
		if inHeredoc {
			checkLine := strings.TrimRight(line, "\r")
			if isStripTabs {
				checkLine = strings.TrimLeft(checkLine, "\t ")
			}
			if checkLine == heredocDelim {
				inHeredoc = false
				heredocDelim = ""
			}
			continue
		}

		result = append(result, line)

		if matches := heredocRe.FindStringSubmatch(line); len(matches) > 0 {
			isStripTabs = matches[1] == "-"
			delim := matches[2]
			if delim == "" {
				delim = matches[3]
			}
			if delim == "" {
				delim = matches[4]
			}
			if delim != "" {
				inHeredoc = true
				heredocDelim = delim
			}
		}
	}
	return strings.Join(result, "\n")
}

func pathMatchesProtectedAsset(p, asset string) bool {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	p = strings.TrimSuffix(filepath.ToSlash(p), "/")
	asset = strings.TrimSuffix(filepath.ToSlash(asset), "/")
	if strings.EqualFold(p, asset) || strings.HasSuffix(strings.ToLower(p), "/"+strings.ToLower(asset)) {
		return true
	}
	return false
}

func splitShellWords(cmd string) []string {
	var words []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			cur.WriteByte(ch)
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
			cur.WriteByte(ch)
		} else if (ch == ' ' || ch == '\t') && !inSingle && !inDouble {
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		} else {
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}

func splitSubCommands(cmd string) []string {
	var subs []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			cur.WriteByte(ch)
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
			cur.WriteByte(ch)
		} else if !inSingle && !inDouble && (ch == '\n' || ch == ';' || ch == '|' || (ch == '&' && i+1 < len(cmd) && cmd[i+1] == '&')) {
			if cur.Len() > 0 {
				subs = append(subs, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
			if ch == '&' {
				i++ // skip second '&'
			}
		} else {
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		subs = append(subs, strings.TrimSpace(cur.String()))
	}
	return subs
}

func isTamperingCommand(cmdStr string) (bool, string) {
	stripped := stripHeredocs(cmdStr)
	lower := strings.ToLower(filepath.ToSlash(stripped))

	protected := []string{
		"policy.cedar",
		".claude/settings.json",
		".claude/hooks",
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
		".bap",
	}

	// Quick check: does the stripped command mention any protected asset?
	hasProtected := false
	for _, p := range protected {
		if strings.Contains(lower, p) {
			hasProtected = true
			break
		}
	}
	if !hasProtected {
		return false, ""
	}

	// 1. Check redirection targets: > target, >> target, 1> target, 2> target
	redirRe := regexp.MustCompile(`(?:[0-9&]?>>?)\s*("[^"]+"|\'[^\']+\'|[^\s;&|]+)`)
	for _, match := range redirRe.FindAllStringSubmatch(stripped, -1) {
		target := match[1]
		for _, p := range protected {
			if pathMatchesProtectedAsset(target, p) {
				return true, fmt.Sprintf("Security Invariant Violation: Direct modification, deletion, or tampering with BAP protected asset %q is strictly forbidden.", p)
			}
		}
	}

	// 2. Check destructive commands across subcommands
	subCmds := splitSubCommands(stripped)
	for _, sub := range subCmds {
		words := splitShellWords(sub)
		if len(words) == 0 {
			continue
		}
		cmdName := strings.ToLower(filepath.Base(strings.Trim(words[0], `"'`)))
		cmdName = strings.TrimSuffix(cmdName, ".exe")

		switch cmdName {
		case "rm", "del", "erase", "remove-item", "unlink", "rmdir", "rd",
			"truncate", "chmod", "attrib", "set-content", "out-file", "add-content":
			for _, arg := range words[1:] {
				if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "/") {
					continue // skip flags
				}
				for _, p := range protected {
					if pathMatchesProtectedAsset(arg, p) {
						return true, fmt.Sprintf("Security Invariant Violation: Direct modification, deletion, or tampering with BAP protected asset %q is strictly forbidden.", p)
					}
				}
			}

		case "mv", "move", "ren", "rename":
			for _, arg := range words[1:] {
				if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "/") {
					continue // skip flags
				}
				for _, p := range protected {
					if pathMatchesProtectedAsset(arg, p) {
						return true, fmt.Sprintf("Security Invariant Violation: Direct modification, deletion, or tampering with BAP protected asset %q is strictly forbidden.", p)
					}
				}
			}

		case "cp", "copy":
			var nonFlags []string
			for _, arg := range words[1:] {
				if !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "/") {
					nonFlags = append(nonFlags, arg)
				}
			}
			if len(nonFlags) >= 2 {
				dest := nonFlags[len(nonFlags)-1]
				for _, p := range protected {
					if pathMatchesProtectedAsset(dest, p) {
						return true, fmt.Sprintf("Security Invariant Violation: Direct modification, deletion, or tampering with BAP protected asset %q is strictly forbidden.", p)
					}
				}
			}

		case "sed":
			isInline := false
			var nonFlags []string
			for _, arg := range words[1:] {
				if strings.Contains(arg, "-i") {
					isInline = true
				} else if !strings.HasPrefix(arg, "-") {
					nonFlags = append(nonFlags, arg)
				}
			}
			if isInline && len(nonFlags) >= 2 {
				dest := nonFlags[len(nonFlags)-1]
				for _, p := range protected {
					if pathMatchesProtectedAsset(dest, p) {
						return true, fmt.Sprintf("Security Invariant Violation: Direct modification, deletion, or tampering with BAP protected asset %q is strictly forbidden.", p)
					}
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
	targetPID, _ := resolveAgentProcess(ppid)
	for _, p := range []int{targetPID, ppid} {
		if p <= 0 {
			continue
		}
		for _, cand := range []string{
			sessionMarkerPathForPID(p),
			filepath.Join("..", sessionMarkerPathForPID(p)),
		} {
			if data, err := os.ReadFile(cand); err == nil {
				var info struct {
					SessionID string `json:"session_id"`
				}
				if json.Unmarshal(data, &info) == nil && info.SessionID != "" {
					return info.SessionID
				}
			}
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			for _, cand := range []string{
				filepath.Join(home, ".bapstate", "sessions", fmt.Sprintf("pid-%d.json", p)),
				filepath.Join(home, ".bap", "sessions", fmt.Sprintf("pid-%d.json", p)),
			} {
				if data, err := os.ReadFile(cand); err == nil {
					var info struct {
						SessionID string `json:"session_id"`
					}
					if json.Unmarshal(data, &info) == nil && info.SessionID != "" {
						return info.SessionID
					}
				}
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
	rawPPID := os.Getppid()
	targetPID, caller := resolveAgentProcess(rawPPID)

	// 1. Check if local kill-switch or freeze blocks startup
	if blocked, reason := isStartupBlocked(); blocked {
		fmt.Fprintf(os.Stderr, "[BAP ZERO-TRUST] 🚨 New Claude Code session BLOCKED: %s\n", reason)
		os.Exit(2)
	}

	appID := caller.AppID
	if appID == "" {
		appID = "claude-code"
	}

	sessionID := os.Getenv("BAP_SESSION_ID")
	if sessionID == "" {
		// Check PID-specific marker already written by launcher or bapedge session-start
		if existingID := resolveSessionID(HookPayload{}); existingID != "" {
			sessionID = existingID
		}
	}
	// A pre-existing session id only means a launcher owns the watcher if that watcher is
	// actually alive; stale markers (PID reuse, crashed watcher) must not suppress startup.
	launcherOwnsWatcher := sessionID != "" && watcherAlive(sessionID)
	if sessionID == "" {
		sessionID = payload.SessionID
	}
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-%s-pid-%d", appID, targetPID)
	}

	serverURL := resolveServerURL()

	// 2. Notify control plane of session start (only if not already registered by launcher)
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	startPayload := map[string]any{
		"session_id":  sessionID,
		"app_id":      appID,
		"caller_path": caller.BinaryPath,
		"caller_hash": caller.BinaryHash,
		"user_id":     username,
		"hostname":    hostname,
		"client_pid":  targetPID,
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
		"session_id":  sessionID,
		"server_url":  serverURL,
		"pid":         targetPID,
		"app_id":      appID,
		"caller_path": caller.BinaryPath,
		"caller_hash": caller.BinaryHash,
		"started_at":  time.Now().UTC(),
	}
	if data, err := json.MarshalIndent(marker, "", "  "); err == nil {
		pMarker := sessionMarkerPathForPID(targetPID)
		_ = os.MkdirAll(filepath.Dir(pMarker), 0700)
		_ = os.WriteFile(pMarker, data, 0600)
		if targetPID != rawPPID {
			_ = os.WriteFile(sessionMarkerPathForPID(rawPPID), data, 0600)
		}
		_ = os.WriteFile(filepath.Join(".bap", "session.json"), data, 0600)
		_ = os.Remove(".bap-session.json")
	}

	// Launch detached bapedge watch thread if not already managed by launcher
	ltdBin := findBinary("bapedge.exe")
	if ltdBin == "" {
		ltdBin = findBinary("bapedge")
	}
	if ltdBin != "" && !launcherOwnsWatcher {
		wCmd := exec.Command(ltdBin, "watch", fmt.Sprintf("--pid=%d", watchPIDFor(targetPID, caller)), fmt.Sprintf("--server=%s", serverURL), fmt.Sprintf("--session-id=%s", sessionID), fmt.Sprintf("--app-id=%s", appID), "--detach")
		_ = wCmd.Start()
	}

	// Valid for both Claude-compatible hooks and Codex lifecycle hooks.
	emitUniversalSuccess()
}

func handleSessionEndHook(payload HookPayload) {
	rawPPID := os.Getppid()
	targetPID, _ := resolveAgentProcess(rawPPID)
	sessionID := resolveSessionID(payload)
	serverURL := resolveServerURL()

	hookLog("handleSessionEndHook: session end hook triggered for session %s (agent pid %d)", sessionID, targetPID)

	// 1. Purge all local session markers and watchers immediately
	cleanupSessionMarkers(sessionID, targetPID)
	if targetPID != rawPPID {
		cleanupSessionMarkers(sessionID, rawPPID)
	}

	// 2. Perform remote teardown asynchronously so the hook returns to Claude in <5ms without timeout/cancellation
	ltdBin := findBinary("bapedge.exe")
	if ltdBin == "" {
		ltdBin = findBinary("bapedge")
	}
	if ltdBin != "" && sessionID != "" {
		endCmd := exec.Command(ltdBin, "session-end", fmt.Sprintf("--server=%s", serverURL), fmt.Sprintf("--session-id=%s", sessionID))
		_ = endCmd.Start()
	} else if sessionID != "" && serverURL != "" {
		go func() {
			endPayload := map[string]any{
				"session_id": sessionID,
				"reason":     "Claude Code session closed gracefully",
			}
			if body, err := json.Marshal(endPayload); err == nil {
				client := getHTTPClient()
				client.Timeout = 1500 * time.Millisecond
				resp, err := client.Post(serverURL+"/api/v1/sessions/end", "application/json", bytes.NewReader(body))
				if err == nil && resp != nil {
					_ = resp.Body.Close()
				}
			}
		}()
	}

	emitUniversalSuccess()
}

func cleanupSessionMarkers(sessionID string, pid int) {
	if sessionID != "" {
		sum := sha256.Sum256([]byte(sessionID))
		hashName := fmt.Sprintf("%x.json", sum[:])
		_ = os.Remove(filepath.Join(".bap", "sessions", hashName))
		_ = os.Remove(filepath.Join(".bapstate", "sessions", hashName))
		_ = os.Remove(filepath.Join(".bap", "prompts", fmt.Sprintf("%x.txt", sum[:])))
		_ = os.Remove(promptPathForSession(sessionID))
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			_ = os.Remove(filepath.Join(home, ".bapstate", "sessions", hashName))
			_ = os.Remove(filepath.Join(home, ".bap", "watchers", sanitizeSessionFileID(sessionID)+".watcher"))
		}
		_ = os.Remove(watcherLivenessPath(sessionID))
	}
	if pid > 0 {
		pidName := fmt.Sprintf("pid-%d.json", pid)
		_ = os.Remove(filepath.Join(".bap", "sessions", pidName))
		_ = os.Remove(filepath.Join(".bapstate", "sessions", pidName))
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			_ = os.Remove(filepath.Join(home, ".bapstate", "sessions", pidName))
		}
	}
	_ = os.Remove(filepath.Join(".bap", "session.json"))
	_ = os.Remove(filepath.Join(".bapstate", "session.json"))
	_ = os.Remove(".bap-session.json")
	_ = os.Remove("../.bap-session.json")
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

// bapUserDir returns the per-user BAP state directory shared by hooks and watchers
// (independent of the workspace cwd).
func bapUserDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".bap")
	}
	return ".bap"
}

func sanitizeSessionFileID(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	return strings.Trim(sb.String(), "-") // identical to bap-edge sanitizeInstanceID for non-empty ids
}

// watcherLivenessPath is touched by `bapedge watch` on every heartbeat tick. It must match
// the path used by bap-edge/cmd/watch.go.
func watcherLivenessPath(sessionID string) string {
	return filepath.Join(bapUserDir(), "watchers", sanitizeSessionFileID(sessionID)+".watcher")
}

// promptSpoolDir holds prompt telemetry that has not yet been acknowledged by the control
// plane; the watcher drains it. Must match bap-edge/cmd/watch.go.
func promptSpoolDir() string {
	return filepath.Join(bapUserDir(), "spool", "prompts")
}

const watcherFreshness = 15 * time.Second

func watcherAlive(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	fi, err := os.Stat(watcherLivenessPath(sessionID))
	return err == nil && time.Since(fi.ModTime()) < watcherFreshness
}

// hookLog appends a diagnostic line so silent hook-side failures can be diagnosed later.
func hookLog(format string, args ...any) {
	dir := bapUserDir()
	_ = os.MkdirAll(dir, 0700)
	p := filepath.Join(dir, "hook.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 1<<20 {
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s [%d] %s\n", time.Now().UTC().Format(time.RFC3339), os.Getpid(), fmt.Sprintf(format, args...))
}

// ensureSessionAndWatcher makes sure a live `bapedge watch` exists for this session, no
// matter how Claude Code was launched. The watcher enrolls the session with the control
// plane and sends the heartbeats that mark the agent online. Fast path is a single stat.
func ensureSessionAndWatcher(sessionID, serverURL string) {
	if sessionID == "" || watcherAlive(sessionID) {
		return
	}
	rawPPID := os.Getppid()
	targetPID, caller := resolveAgentProcess(rawPPID)
	ltdBin := findBinary("bapedge.exe")
	if _, err := os.Stat(ltdBin); err != nil {
		if alt := findBinary("bapedge"); alt != "" {
			ltdBin = alt
		}
	}
	if _, err := os.Stat(ltdBin); err != nil {
		if p, lerr := exec.LookPath("bapedge"); lerr == nil {
			ltdBin = p
		} else {
			hookLog("ensureSessionAndWatcher: bapedge binary not found; session %s will not report liveness", sessionID)
			return
		}
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}

	// 1. Write PID markers immediately so all concurrent/child hooks share this session
	marker := map[string]any{
		"session_id":  sessionID,
		"server_url":  serverURL,
		"pid":         targetPID,
		"app_id":      caller.AppID,
		"caller_path": caller.BinaryPath,
		"caller_hash": caller.BinaryHash,
		"started_at":  time.Now().UTC(),
	}
	if data, err := json.MarshalIndent(marker, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Join(".bap", "sessions"), 0700)
		_ = os.WriteFile(sessionMarkerPathForPID(targetPID), data, 0600)
		if targetPID != rawPPID && rawPPID > 0 {
			_ = os.WriteFile(sessionMarkerPathForPID(rawPPID), data, 0600)
		}
		_ = os.WriteFile(filepath.Join(".bap", "session.json"), data, 0600)
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			_ = os.MkdirAll(filepath.Join(home, ".bapstate", "sessions"), 0700)
			_ = os.WriteFile(filepath.Join(home, ".bapstate", "sessions", fmt.Sprintf("pid-%d.json", targetPID)), data, 0600)
		}
	}

	// 2. Register session immediately with control plane
	startPayload := map[string]any{
		"session_id":  sessionID,
		"app_id":      caller.AppID,
		"caller_path": caller.BinaryPath,
		"caller_hash": caller.BinaryHash,
		"user_id":     username,
		"hostname":    hostname,
		"client_pid":  targetPID,
	}
	if body, err := json.Marshal(startPayload); err == nil {
		client := getHTTPClient()
		client.Timeout = 1200 * time.Millisecond
		_, _ = client.Post(serverURL+"/api/v1/sessions/start", "application/json", bytes.NewReader(body))
	}

	// 3. Spawn detached watcher monitoring the true root agent PID
	wCmd := exec.Command(ltdBin, "watch", fmt.Sprintf("--pid=%d", watchPIDFor(targetPID, caller)), fmt.Sprintf("--server=%s", serverURL), fmt.Sprintf("--session-id=%s", sessionID), fmt.Sprintf("--app-id=%s", caller.AppID), "--detach")
	if err := wCmd.Start(); err != nil {
		hookLog("ensureSessionAndWatcher: failed to spawn watcher for %s: %v", sessionID, err)
		return
	}
	_ = wCmd.Process.Release()
	hookLog("ensureSessionAndWatcher: spawned watcher for session %s (agent pid %d [%s], server %s)", sessionID, targetPID, caller.AppID, serverURL)
}

// spoolPrompt durably records a prompt event before delivery so a timeout or an
// unregistered session cannot lose it. Returns the spool file path ("" on failure).
func spoolPrompt(sessionID string, body []byte) string {
	dir := promptSpoolDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		hookLog("spoolPrompt: %v", err)
		return ""
	}
	name := fmt.Sprintf("%020d-%d.json", time.Now().UnixNano(), os.Getpid())
	p := filepath.Join(dir, name)
	env, _ := json.Marshal(map[string]any{"session_id": sessionID, "body": json.RawMessage(body)})
	if err := os.WriteFile(p, env, 0600); err != nil {
		hookLog("spoolPrompt: %v", err)
		return ""
	}
	return p
}

func handleUserPromptHook(payload HookPayload) {
	prompt := strings.TrimSpace(payload.UserPrompt)
	if prompt == "" {
		prompt = strings.TrimSpace(payload.UserPromptCamel)
	}
	if prompt == "" {
		prompt = strings.TrimSpace(payload.Prompt)
	}
	tPath := payload.TranscriptPath
	if tPath == "" {
		tPath = payload.TranscriptPathSnake
	}
	if prompt == "" {
		prompt = lastUserPromptText(tPath, payload.ConversationID)
	}

	serverURL := resolveServerURL()
	sessionID := resolveSessionID(payload)
	ppid := os.Getppid()
	targetPID, caller := resolveAgentProcess(ppid)
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-%s-pid-%d", caller.AppID, targetPID)
	}

	// Zero-Trust Revocation Check: STOP taking user inputs if revoked
	if revoked, reason := isSessionRevoked(serverURL, sessionID); revoked {
		outputPromptBlocked(sessionID, reason)
		return
	}

	// Self-heal: governed launcher or not, make sure this session has a live watcher
	// (registration + heartbeats) before telemetry is sent.
	ensureSessionAndWatcher(sessionID, serverURL)

	producer := "claude-lifecycle-hook"
	if payload.ConversationID != "" || caller.AppID == "antigravity" {
		producer = "antigravity-hook"
	} else if caller.AppID == "codex" || strings.EqualFold(os.Getenv("LTD_SOURCE"), "codex") {
		producer = "codex-lifecycle-hook"
	}
	capturePrompt := shouldCaptureUserPrompt()

	// Gather prompt to send: if the prompt was passed in the hook payload, send only that
	// prompt. Only fall back to transcript extraction if prompt text was empty.
	var promptsToSend []string
	if prompt != "" {
		promptsToSend = []string{prompt}
	} else if tPath != "" || payload.ConversationID != "" {
		if latest := lastUserPromptText(tPath, payload.ConversationID); latest != "" {
			promptsToSend = []string{latest}
		}
	}
	if len(promptsToSend) == 0 && prompt != "" {
		promptsToSend = []string{prompt}
	}

	for _, p := range promptsToSend {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		intent := classifyIntent(p)
		promptDigest := sha256.Sum256([]byte(p))
		promptHash := fmt.Sprintf("%x", promptDigest[:])

		if capturePrompt {
			writeSessionPrompt(sessionID, p)
		} else if sessionID != "" {
			_ = os.Remove(promptPathForSession(sessionID))
		}

		if sessionID != "" && serverURL != "" {
			request := map[string]any{
				"session_id":             sessionID,
				"producer":               producer,
				"intent":                 intent,
				"prompt_hash":            promptHash,
				"prompt_capture_enabled": capturePrompt,
				"parent_pid":             ppid,
			}
			if capturePrompt {
				request["user_prompt"] = p
			}
			reqBody, _ := json.Marshal(request)
			spoolPath := spoolPrompt(sessionID, reqBody)
			client := getHTTPClient()
			client.Timeout = 1200 * time.Millisecond
			resp, err := client.Post(serverURL+"/api/v1/sessions/prompt", "application/json", bytes.NewReader(reqBody))
			if err != nil || resp == nil {
				hookLog("prompt delivery deferred to spool (session %s): %v", sessionID, err)
			} else {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusForbidden {
					if spoolPath != "" {
						_ = os.Remove(spoolPath)
					}
					// Control plane rejected prompt due to revocation
					outputPromptBlocked(sessionID, "Session authority revoked by administrator on control plane")
					return
				}
				if resp.StatusCode == http.StatusOK {
					if spoolPath != "" {
						_ = os.Remove(spoolPath)
					}
				} else {
					// e.g. 404 while the session is not enrolled yet: keep spooled for replay
					hookLog("prompt POST returned HTTP %d (session %s); kept in spool", resp.StatusCode, sessionID)
				}
			}
		}
	}

	// Valid for both Claude-compatible hooks and Codex lifecycle hooks.
	emitUniversalSuccess()
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

	// CLI argument flag overrides (e.g. interceptor.exe --event SessionStart / PreToolUse)
	for i, arg := range os.Args {
		if (arg == "--event" || arg == "-event") && i+1 < len(os.Args) {
			payload.HookEventName = os.Args[i+1]
		}
		if (arg == "--decision-style" || arg == "-decision-style" || arg == "--format" || arg == "-format") && i+1 < len(os.Args) {
			payload.DecisionStyle = os.Args[i+1]
		}
	}

	normalizeHookPayload(&payload)
	if payload.DecisionStyle != "" {
		activeDecisionStyle = payload.DecisionStyle
	}
	if payload.AppID != "" {
		activeCallerAppID = payload.AppID
	}

	// Normalize Antigravity fields if present
	if payload.ConversationID != "" && payload.SessionID == "" {
		payload.SessionID = payload.ConversationID
	}
	if payload.ToolCall != nil {
		if payload.ToolName == "" {
			payload.ToolName = payload.ToolCall.Name
		}
		if payload.ToolInput.Command == "" && payload.ToolCall.Args != nil {
			if cmd, ok := payload.ToolCall.Args["CommandLine"].(string); ok {
				payload.ToolInput.Command = cmd
			}
		}
		if payload.HookEventName == "" {
			payload.HookEventName = "PreToolUse"
		}
	}
	if strings.EqualFold(payload.HookEventName, "PreInvocation") {
		payload.HookEventName = "UserPromptSubmit"
	}

	// 2. Lifecycle Hook Handling: SessionStart
	if strings.EqualFold(payload.HookEventName, "SessionStart") {
		handleSessionStartHook(payload)
		return
	}

	// 3. Lifecycle Hook Handling: SessionEnd / SessionStop
	if strings.EqualFold(payload.HookEventName, "SessionEnd") || strings.EqualFold(payload.HookEventName, "SessionStop") {
		handleSessionEndHook(payload)
		return
	}

	// 3b. Lifecycle Hook Handling: Stop (agent finished replying)
	if strings.EqualFold(payload.HookEventName, "Stop") {
		handleStopHook(payload)
		return
	}

	// 4. Lifecycle Hook Handling: UserPromptSubmit / UserPrompt
	if strings.EqualFold(payload.HookEventName, "UserPromptSubmit") || strings.EqualFold(payload.HookEventName, "UserPrompt") {
		handleUserPromptHook(payload)
		return
	}

	sessionID := resolveSessionID(payload)
	ppid := os.Getppid()
	targetPID, caller := resolveAgentProcess(ppid)
	if activeCallerAppID == "" {
		activeCallerAppID = caller.AppID
	}
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-%s-pid-%d", caller.AppID, targetPID)
	}
	if revoked, reason := isSessionRevoked(resolveServerURL(), sessionID); revoked {
		outputDecision("deny", reason, "This session cannot perform further governed tool actions.")
		return
	}
	ensureSessionAndWatcher(sessionID, resolveServerURL())

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
			if active, banner := devOverrideActive(); active {
				hookLog("DEV OVERRIDE allowed %s of protected asset %s (session %s)", payload.ToolName, targetFile, sessionID)
				fmt.Fprintln(os.Stderr, banner)
			} else {
				outputDecision("deny", fmt.Sprintf("Security Invariant Violation: Direct modification or tampering with BAP protected asset %q is strictly forbidden", targetFile), "Modifying or tampering with BAP configuration, policies, hooks, or binaries is prohibited.")
				return
			}
		}

		// Secret protection applies to all files inside or outside workspace
		if strings.Contains(normPath, ".env") || strings.Contains(normPath, ".aws") || strings.Contains(normPath, ".ssh") || strings.Contains(normPath, "id_rsa") || strings.Contains(normPath, "id_ed25519") {
			outputDecision("deny", fmt.Sprintf("Access to sensitive credential file %q is strictly forbidden by policy", targetFile), "Sensitive credential file access blocked")
			return
		}

		// Mutating tools (Edit, Write) outside workspace are strictly forbidden unless step-up approved
		if (payload.ToolName == "Edit" || payload.ToolName == "Write") && isPathOutsideWorkspace(workspaceRoot, targetFile) {
			stepUpDec := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_STEPUP_DECISION")))
			if stepUpDec == "approve" || stepUpDec == "once" || stepUpDec == "allow" || isSessionTrustGranted(sessionID, targetFile, payload.ToolName) {
				outputDecision("allow", "", fmt.Sprintf("[STEP-UP AUTHORIZED] Human operator authorized modifying file outside workspace: %s", targetFile))
				return
			}
			if authorized, scope := isTargetAuthorized(workspaceRoot, sessionID, targetFile, "write"); authorized {
				outputDecision("allow", "", fmt.Sprintf("[STEP-UP AUTHORIZED: %s TRUST] User granted cross-folder write permission for %s", strings.ToUpper(scope), targetFile))
				return
			}
			if stepUpDec == "project" || stepUpDec == "p" {
				_ = grantTargetPermission(workspaceRoot, sessionID, targetFile, "project", []string{"write"})
				outputDecision("allow", "", fmt.Sprintf("[STEP-UP AUTHORIZED: PROJECT TRUST] User granted cross-folder write permission for %s", targetFile))
				return
			}
			if stepUpDec == "global" || stepUpDec == "g" {
				_ = grantTargetPermission(workspaceRoot, sessionID, targetFile, "global", []string{"write"})
				outputDecision("allow", "", fmt.Sprintf("[STEP-UP AUTHORIZED: GLOBAL TRUST] User granted cross-folder write permission for %s", targetFile))
				return
			}
			if stepUpDec == "session" || stepUpDec == "s" {
				_ = grantTargetPermission(workspaceRoot, sessionID, targetFile, "session", []string{"write"})
				outputDecision("allow", "", fmt.Sprintf("[STEP-UP AUTHORIZED: SESSION TRUST] User granted cross-folder write permission for %s", targetFile))
				return
			}
			outputDecision("deny", fmt.Sprintf("Modifying files outside workspace is forbidden for file %q", targetFile), fmt.Sprintf("Writing or modifying files outside the project root is prohibited. Authorize via 'bapedge trust %q --project' (or --session / --global).", targetFile))
			return
		}

		// Read-only inspection tools (Read, View) are permitted for cross-project dependencies and documentation
		toolLower := strings.ToLower(payload.ToolName)
		if isSafeFileTool(toolLower) {
			outputDecision("allow", "", "File inspection permitted")
			return
		}
	}

	// 5. Process Command execution (Bash or generic command) vs Subagents & Inspection Tools
	command := strings.TrimSpace(payload.ToolInput.Command)
	if command == "" {
		toolLower := strings.ToLower(payload.ToolName)
		if isSafeFileTool(toolLower) {
			outputDecision("allow", "", "File operation permitted")
			return
		}

		// Allow subagents, code search, and directory exploration tools
		// (e.g. search_code_subagent, Agent, Task, Glob, Grep, LS, ListDirectory, find_by_name)
		if isSafeSubagentOrInspectionTool(toolLower) {
			outputDecision("allow", "", fmt.Sprintf("Inspection or subagent tool %q permitted by zero-trust policy", payload.ToolName))
			return
		}

		// Allow any non-shell tool (e.g. MCP tools, model query tools)
		if payload.ToolName != "" && !isShellTool(toolLower) {
			outputDecision("allow", "", fmt.Sprintf("Non-shell tool %q permitted", payload.ToolName))
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
		_ = ppid
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
		targetPID, caller := resolveAgentProcess(ppid)
		sessionBytes := []byte(fmt.Sprintf(`{"session_id":"%s","server_url":"%s","pid":%d,"app_id":"%s"}`, sessionID, serverURL, targetPID, caller.AppID))
		pMarker := sessionMarkerPathForPID(targetPID)
		_ = os.MkdirAll(filepath.Dir(pMarker), 0700)
		_ = os.WriteFile(pMarker, sessionBytes, 0600)
		if targetPID != ppid {
			_ = os.WriteFile(sessionMarkerPathForPID(ppid), sessionBytes, 0600)
		}
		_ = os.WriteFile(filepath.Join(".bap", "session.json"), sessionBytes, 0600)
		_ = os.Remove(".bap-session.json")
		ltdBin := findBinary("bapedge.exe")
		if ltdBin == "" {
			ltdBin = findBinary("bapedge")
		}
		if ltdBin != "" {
			wCmd := exec.Command(ltdBin, "watch", fmt.Sprintf("--pid=%d", watchPIDFor(targetPID, caller)), fmt.Sprintf("--server=%s", serverURL), fmt.Sprintf("--session-id=%s", sessionID), fmt.Sprintf("--app-id=%s", caller.AppID), "--detach")
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
		mode := resolveEnforcementMode()
		if mode == "audit" || mode == "shadow" {
			hookLog("AUDIT MODE allowed tamper-guarded command (session %s): %s", sessionID, tamperReason)
			fmt.Fprintf(os.Stderr, "[BAP AUDIT MODE] Policy violation detected: %s. Execution permitted in audit mode.\n", tamperReason)
		} else if active, banner := devOverrideActive(); active {
			hookLog("DEV OVERRIDE allowed tamper-guarded command (session %s): %s", sessionID, tamperReason)
			fmt.Fprintln(os.Stderr, banner)
		} else {
			outputDecision("deny", tamperReason, "Direct modification or tampering with BAP configuration, policies, hooks, or binaries is prohibited.")
			return
		}
	}
	if checkCommandWorkspaceEscape(workspaceRoot, command) {
		isMutating := isMutatingShellCommand(command)
		target := extractCommandTarget(command)
		if isMutating && target != "" {
			if auth, _ := isTargetAuthorized(workspaceRoot, sessionID, target, "write"); !auth {
				stepUpDec := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_STEPUP_DECISION")))
				if stepUpDec == "approve" || stepUpDec == "once" || stepUpDec == "allow" {
					// allowed to proceed to bapedge check
				} else if stepUpDec == "project" || stepUpDec == "p" {
					_ = grantTargetPermission(workspaceRoot, sessionID, target, "project", []string{"write", "delete"})
				} else if stepUpDec == "global" || stepUpDec == "g" {
					_ = grantTargetPermission(workspaceRoot, sessionID, target, "global", []string{"write", "delete"})
				} else if stepUpDec == "session" || stepUpDec == "s" {
					_ = grantTargetPermission(workspaceRoot, sessionID, target, "session", []string{"write", "delete"})
				} else {
					mode := resolveEnforcementMode()
					if mode == "audit" || mode == "shadow" {
						hookLog("AUDIT MODE allowed workspace traversal (session %s): %s", sessionID, target)
						fmt.Fprintf(os.Stderr, "[BAP AUDIT MODE] Directory traversal outside workspace detected: %s. Execution permitted in audit mode.\n", target)
					} else {
						outputDecision("deny", fmt.Sprintf("Directory traversal outside workspace is forbidden in command: %s", command), fmt.Sprintf("Commands modifying files outside workspace require authorization. Authorize via 'bapedge trust %q --project' (or --session / --global).", target))
						return
					}
				}
			}
		}
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
	caller = inspectCallerProcess(ppid)
	callerSource := caller.AppID
	if callerSource == "" {
		callerSource = "claude-code"
	}
	execArgs := []string{"check", "--source", callerSource, "--json", "--cmd-b64", cmdB64}
	if sessionID != "" {
		execArgs = []string{"check", "--source", callerSource, "--session-id", sessionID, "--json", "--cmd-b64", cmdB64}
	}
	if caller.BinaryPath != "" {
		execArgs = append(execArgs, "--caller-binary", caller.BinaryPath)
	}
	if caller.BinaryHash != "" {
		execArgs = append(execArgs, "--caller-hash", caller.BinaryHash)
	}

	cmd := exec.Command(ltdBin, execArgs...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "BAP_SESSION_ID="+sessionID)
	cmd.Env = append(cmd.Env, "LTD_SOURCE="+callerSource)
	if caller.BinaryPath != "" {
		cmd.Env = append(cmd.Env, "BAP_CALLER_BINARY="+caller.BinaryPath, "LTD_CALLER_BINARY="+caller.BinaryPath)
	}
	if caller.BinaryHash != "" {
		cmd.Env = append(cmd.Env, "BAP_CALLER_HASH="+caller.BinaryHash, "LTD_CALLER_HASH="+caller.BinaryHash)
	}

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
		caller := inspectCallerProcess(ppid)
		callerSource := caller.AppID
		if callerSource == "" {
			callerSource = "claude-code"
		}
		rewritten := fmt.Sprintf(`%s exec --source %s --session-id %s --cmd-b64 %s`, ltdBin, callerSource, sessionID, cmdB64)
		if caller.BinaryPath != "" {
			rewritten = fmt.Sprintf(`%s --caller-binary "%s"`, rewritten, caller.BinaryPath)
		}
		if caller.BinaryHash != "" {
			rewritten = fmt.Sprintf(`%s --caller-hash "%s"`, rewritten, caller.BinaryHash)
		}
		outputDecisionWithUpdatedInput("allow", "", "Command authorized by BAP Cedar policy - routed to BAP broker sandbox", &ToolInput{Command: rewritten})
	} else {
		mode := resolveEnforcementMode()
		if mode == "audit" || mode == "shadow" {
			outputDecision("allow", "", fmt.Sprintf("[BAP AUDIT MODE] Policy violation detected: %s. Execution permitted in audit mode.", execResp.Reason))
			return
		}
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
	// 2b. Check permanent user home and Program Files directories
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		for _, cand := range []string{
			filepath.Join(homeDir, ".bap", "bin", name),
			filepath.Join(homeDir, ".bap", name),
			filepath.Join(homeDir, ".claude", "hooks", name),
		} {
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	for _, progDir := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "BAP", "bin", name),
		filepath.Join(os.Getenv("ProgramFiles"), "BAP", name),
		"C:\\Program Files\\BAP\\bin\\" + name,
		"C:\\Program Files\\BAP\\" + name,
	} {
		if progDir != "" {
			if _, err := os.Stat(progDir); err == nil {
				return progDir
			}
		}
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
// or generic tool runner schema depending on caller identity and requested decision style.
func outputDecisionWithUpdatedInput(decision, reason, context string, updatedInput *ToolInput) {
	// If updatedInput has command, mirror across alternate tool input aliases
	if updatedInput != nil {
		if updatedInput.Command != "" {
			if updatedInput.Cmd == "" {
				updatedInput.Cmd = updatedInput.Command
			}
			if updatedInput.CommandLine == "" {
				updatedInput.CommandLine = updatedInput.Command
			}
		}
		if updatedInput.FilePath != "" {
			if updatedInput.Path == "" {
				updatedInput.Path = updatedInput.FilePath
			}
			if updatedInput.FilePathCamel == "" {
				updatedInput.FilePathCamel = updatedInput.FilePath
			}
		}
	}

	resp := HookResponse{
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision, // Always "allow" or "deny" for Claude Code permissionDecision
			PermissionDecisionReason: reason,
			AdditionalContext:        context,
			UpdatedInput:             updatedInput,
		},
		UpdatedInput: updatedInput,
	}

	// Determine decision style:
	// 1. Explicit style ("allow" vs "approve", or agent name)
	// 2. Caller AppID: "claude-code" (or any claude variant) requires top-level decision to be "approve" / "block".
	//    Non-Claude tools (Codex, Antigravity, Copilot, Cursor, generic runners) expect "allow" / "deny".
	style := strings.ToLower(strings.TrimSpace(activeDecisionStyle))
	if style == "" {
		style = strings.ToLower(strings.TrimSpace(os.Getenv("BAP_HOOK_DECISION_STYLE")))
	}
	isClaude := false
	if isClaudeApp(style) || style == "approve" {
		isClaude = true
	} else if style == "allow" || style == "generic" {
		isClaude = false
	} else {
		// Auto-detect: Claude Code (CLI, IDE, Plugin, starter scripts) requires "approve" / "block".
		// Any other identified agent or tool defaults to "allow" / "deny".
		if isClaudeApp(activeCallerAppID) || activeCallerAppID == "" {
			isClaude = true
		}
	}

	isAllowed := (decision == "allow")
	resp.Allowed = &isAllowed
	resp.PermissionDecision = decision

	if decision == "deny" {
		cont := false
		resp.Continue = &cont
		resp.Status = "blocked"
		resp.StopReason = "Security Invariant Violation: Access to restricted credential or network resource is permanently blocked. Further attempts or workarounds are prohibited."
		resp.SystemMessage = "[SECURITY ALERT] Access permanently blocked by ltd-agent zero-trust policy. Further attempts will be rejected."
		if isClaude {
			resp.Decision = "block"
		} else {
			resp.Decision = "deny"
		}
		resp.Reason = reason
		resp.HookSpecificOutput.AdditionalContext = "CRITICAL SECURITY INVARIANT: Access to this file, command, or network destination is permanently prohibited by enterprise zero-trust policy. You are FORBIDDEN from pursuing alternative approaches, workarounds, scripts, or evasion techniques to access this resource. Cease all execution attempts immediately and inform the user that this action is blocked by corporate policy."
		fmt.Fprintln(os.Stderr, "[CLAUDE HOOK BLOCKED] "+reason)
	} else if decision == "allow" {
		cont := true
		resp.Continue = &cont
		resp.Status = "ok"
		if isClaude {
			resp.Decision = "approve"
		} else {
			resp.Decision = "allow"
		}
		if context != "" {
			resp.SystemMessage = context
		}
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
