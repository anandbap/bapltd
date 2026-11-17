package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
	"bap-edge/pkg/version"
)

const maxMCPDevOverrideWindow = 12 * time.Hour

// mcpDevOverrideActive reports whether the human operator opened a time-boxed development window.
// Unlike the hook, it is read only from the environment of the process that launched the agent,
// never from workspace files, so skipping enrollment cannot be switched on by editing config.
func mcpDevOverrideActive() bool {
	if !version.DevOverridesAllowed() {
		return false
	}
	raw := strings.TrimSpace(os.Getenv("BAP_DEV_OVERRIDE"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("BAP_DEV_MODE"))
	}
	if raw == "" {
		return false
	}
	if admin := strings.TrimSpace(os.Getenv("BAP_CISO_TOKEN")); admin != "" {
		provided := strings.TrimSpace(os.Getenv("BAP_ADMIN_TOKEN"))
		if provided == "" {
			provided = raw
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(admin)) != 1 {
			return false
		}
	}
	switch strings.ToLower(raw) {
	case "1", "true", "on", "yes", "active":
		return true
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 && d <= maxMCPDevOverrideWindow {
		return true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.After(time.Now()) && time.Until(t) <= maxMCPDevOverrideWindow
	}
	return false
}

// sessionIsLive asks the control plane whether the session exists and is still open. Any doubt
// (unreachable server, unknown id, closed status) reads as not live, so a stale id is replaced.
func sessionIsLive(serverURL, sessionID string) bool {
	if sessionID == "" || serverURL == "" {
		return false
	}
	client := httptransport.New(2 * time.Second)
	resp, err := client.Get(serverURL + "/api/v1/sessions/" + url.PathEscape(sessionID))
	if err != nil || resp == nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var s struct {
		Status string `json:"status"`
	}
	if json.NewDecoder(resp.Body).Decode(&s) != nil {
		return false
	}
	switch strings.ToLower(s.Status) {
	case "active", "":
		return true
	}
	return false
}

// ensureMCPSession enrolls an Antigravity session when the MCP server was started without the
// BAP launcher (for example by opening the IDE directly). It returns the session id the server
// should use. A live session id handed down by the launcher is kept untouched.
//
// The id is derived from the parent (IDE) process so repeated MCP restarts inside one IDE run
// share a single session, and a stale id from a previous run is never reused.
func ensureMCPSession(sessionID, serverURL string) string {
	ltdSource := strings.TrimSpace(os.Getenv("LTD_SOURCE"))
	if !strings.EqualFold(ltdSource, "antigravity") {
		// Auto-detect if caller/parent process is Antigravity (agy.exe, antigravity.exe, language_server.exe)
		if procs, err := listAgentProcesses(); err == nil {
			if obs, ok := observedCaller(os.Getppid(), procs); ok && agentApp(obs.Name) == "antigravity" {
				ltdSource = "antigravity"
				_ = os.Setenv("LTD_SOURCE", "antigravity")
			} else {
				return sessionID
			}
		} else {
			return sessionID
		}
	}
	if mcpDevOverrideActive() {
		fmt.Fprintln(os.Stderr, "[BAP DEV OVERRIDE ACTIVE] Antigravity self-enrollment skipped; this session is not governed or reported.")
		return sessionID
	}
	if sessionID == "" {
		sessionID = strings.TrimSpace(os.Getenv("BAP_SESSION_ID"))
	}
	if sessionID != "" && (IsSessionActive(sessionID) || sessionIsLive(serverURL, sessionID)) {
		startAntigravityPromptTail(sessionID, serverURL)
		return sessionID
	}
	ppid := os.Getppid()
	if sessionID == "" {
		if existing := findActiveNativeSession("antigravity", ppid); existing != "" {
			_ = os.Setenv("BAP_SESSION_ID", existing)
			startAntigravityPromptTail(existing, serverURL)
			return existing
		}
	}
	targetID := sessionID
	if targetID == "" {
		targetID = fmt.Sprintf("sess-antigravity-%d", ppid)
	}
	if err := RunSessionStart([]string{
		"--server=" + serverURL,
		"--session-id=" + targetID,
		"--app-id=antigravity",
		fmt.Sprintf("--pid=%d", ppid),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[BAP] Antigravity self-enrollment failed: %v\n", err)
		return sessionID
	}
	os.Setenv("BAP_SESSION_ID", targetID)
	startAntigravityPromptTail(targetID, serverURL)
	return targetID
}

var (
	promptTailMu     sync.Mutex
	promptTailActive bool
	promptTailCancel context.CancelFunc
)

func promptTailLockPath(sessionIDs ...string) string {
	sess := ""
	if len(sessionIDs) > 0 && sessionIDs[0] != "" {
		sess = "_" + cleanSessionID(sessionIDs[0])
	}
	return filepath.Join(state.Dir(), fmt.Sprintf("antigravity_prompt_tail%s.lock", sess))
}

func cleanSessionID(sessionID string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, sessionID)
}

func isPromptTailerRunningElsewhere(sessionIDs ...string) bool {
	lockFile := promptTailLockPath(sessionIDs...)
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return false
	}
	var lockInfo struct {
		PID       int       `json:"pid"`
		SessionID string    `json:"session_id"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if json.Unmarshal(data, &lockInfo) != nil || lockInfo.PID <= 0 {
		return false
	}
	if lockInfo.PID == os.Getpid() {
		return false
	}
	if isProcessAlive(lockInfo.PID) && time.Since(lockInfo.UpdatedAt) < 15*time.Second {
		return true
	}
	return false
}

func updatePromptTailLock(sessionID string) {
	lockFile := promptTailLockPath(sessionID)
	lockInfo := map[string]any{
		"pid":        os.Getpid(),
		"session_id": sessionID,
		"updated_at": time.Now().UTC(),
	}
	if data, err := json.Marshal(lockInfo); err == nil {
		_ = os.WriteFile(lockFile, data, 0600)
	}
}

func releasePromptTailLock(sessionIDs ...string) {
	lockFile := promptTailLockPath(sessionIDs...)
	if data, err := os.ReadFile(lockFile); err == nil {
		var lockInfo struct {
			PID int `json:"pid"`
		}
		if json.Unmarshal(data, &lockInfo) == nil && lockInfo.PID == os.Getpid() {
			_ = os.Remove(lockFile)
		}
	}
}

func isPromptHashSent(pHash string) bool {
	if pHash == "" {
		return false
	}
	p := filepath.Join(state.PromptsDir(), fmt.Sprintf("hash-%s.sent", pHash))
	_, err := os.Stat(p)
	return err == nil
}

func markPromptHashSent(pHash string) {
	if pHash == "" {
		return
	}
	p := filepath.Join(state.PromptsDir(), fmt.Sprintf("hash-%s.sent", pHash))
	_ = os.WriteFile(p, []byte(time.Now().UTC().Format(time.RFC3339)), 0600)
}

func isTestEnv() bool {
	if flag.Lookup("test.v") != nil {
		return true
	}
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.") {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(os.Args[0]))
	return strings.HasSuffix(base, ".test.exe") || strings.HasSuffix(base, ".test")
}

func startAntigravityPromptTail(sessionID, serverURL string) func() {
	if serverURL == "" || sessionID == "" || isTestEnv() {
		return nil
	}
	if isPromptTailerRunningElsewhere(sessionID) {
		return nil
	}
	promptTailMu.Lock()
	defer promptTailMu.Unlock()
	if promptTailActive {
		return promptTailCancel
	}
	ctx, cancel := context.WithCancel(context.Background())
	promptTailCancel = cancel
	promptTailActive = true

	go runAntigravityPromptTailLoop(ctx, sessionID, serverURL)
	return cancel
}

func runAntigravityPromptTailLoop(ctx context.Context, sessionID, serverURL string) {
	updatePromptTailLock(sessionID)
	defer func() {
		releasePromptTailLock(sessionID)
		promptTailMu.Lock()
		promptTailActive = false
		promptTailCancel = nil
		promptTailMu.Unlock()
	}()

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}

	isIDE := strings.Contains(strings.ToLower(sessionID), "ide")
	isCLI := strings.Contains(strings.ToLower(sessionID), "cli")

	searchRoots := []string{}
	if isCLI {
		cliRoot := filepath.Join(home, ".gemini", "antigravity-cli", "brain")
		if fi, err := os.Stat(cliRoot); err == nil && fi.IsDir() {
			searchRoots = append(searchRoots, cliRoot)
		} else {
			searchRoots = append(searchRoots, filepath.Join(home, ".gemini", "antigravity", "brain"))
		}
	} else if isIDE {
		searchRoots = append(searchRoots, filepath.Join(home, ".gemini", "antigravity", "brain"))
	} else {
		searchRoots = []string{
			filepath.Join(home, ".gemini", "antigravity-cli", "brain"),
			filepath.Join(home, ".gemini", "antigravity", "brain"),
		}
	}

	producer := "antigravity-cli"
	if isIDE {
		producer = "antigravity-ide"
	}

	// Only prompts typed after this tailer started belong to this session. Everything already in
	// the transcripts is history: baseline it instead of replaying it into the session.
	offsets := make(map[string]int64)
	tailStart := time.Now()
	baselineTranscripts(searchRoots, offsets, tailStart, func(prompt string) {
		postTailedPrompt(httptransport.New(2*time.Second), sessionID, serverURL, "", 0, prompt)
	})
	client := httptransport.New(2 * time.Second)
	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updatePromptTailLock(sessionID)
		}

		for _, root := range searchRoots {
			fi, err := os.Stat(root)
			if err != nil || !fi.IsDir() {
				continue
			}

			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				for _, p := range transcriptCandidates(root, e.Name()) {
					prompts, spans, next, ok := readNewTranscriptPrompts(p, offsets)
					if !ok {
						continue
					}
					offsets[p] = next
					for i, userReq := range prompts {
						// Claim by file position, not prompt text: repeating "continue" is a new turn,
						// while two tailers looking at the same line must not both report it.
						claim := promptClaimKey(p, spans[i])
						if isPromptHashSent(claim) {
							continue
						}
						markPromptHashSent(claim)
						h := sha256.Sum256([]byte(userReq))
						pHash := fmt.Sprintf("%x", h[:])

						payload := map[string]any{
							"session_id":             sessionID,
							"user_prompt":            userReq,
							"producer":               producer,
							"prompt_hash":            pHash,
							"prompt_capture_enabled": true,
							"intent": map[string]any{
								"primary":            "INVESTIGATION",
								"confidence":         0.90,
								"classifier_version": "bap-edge-rules-v1",
								"source":             "antigravity-transcript-tail",
							},
						}
						data, err := json.Marshal(payload)
						if err != nil {
							continue
						}
						reqURL := strings.TrimRight(serverURL, "/") + "/api/v1/sessions/prompt"
						resp, err := client.Post(reqURL, "application/json", bytes.NewReader(data))
						if err == nil && resp != nil {
							_ = resp.Body.Close()
						}
					}
				}
			}
		}
	}
}

// transcriptCandidates lists the transcript files a conversation directory may contain.
func transcriptCandidates(root, conv string) []string {
	return []string{
		filepath.Join(root, conv, ".system_generated", "logs", "transcript.jsonl"),
		filepath.Join(root, conv, "transcript.jsonl"),
	}
}

// promptClaimKey identifies one transcript line (file + byte offset), independent of its text.
func promptClaimKey(path string, offset int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", filepath.Clean(path), offset)))
	return hex.EncodeToString(h[:])
}

// parsePromptLine extracts the user's prompt from one transcript line, or "" when the line is
// not a user turn. JSON lines carrying a type other than USER_INPUT (assistant text, tool output
// that merely quotes a <USER_REQUEST> block) are never prompts.
func parsePromptLine(l string) string {
	l = strings.TrimSpace(l)
	if l == "" {
		return ""
	}
	isUserInput := strings.Contains(l, `"type":"USER_INPUT"`) || strings.Contains(l, `"type": "USER_INPUT"`)
	var prompt string
	if strings.HasPrefix(l, "{") {
		var obj struct {
			Type    string `json:"type"`
			Content string `json:"content"`
		}
		if json.Unmarshal([]byte(l), &obj) != nil || (obj.Type != "" && obj.Type != "USER_INPUT") || obj.Content == "" {
			return ""
		}
		raw := obj.Content
		if start := strings.Index(raw, "<USER_REQUEST>"); start != -1 {
			start += len("<USER_REQUEST>")
			if end := strings.Index(raw[start:], "</USER_REQUEST>"); end != -1 {
				prompt = raw[start : start+end]
			}
		} else if isUserInput {
			prompt = raw
		}
	} else if start := strings.Index(l, "<USER_REQUEST>"); start != -1 {
		start += len("<USER_REQUEST>")
		if end := strings.Index(l[start:], "</USER_REQUEST>"); end != -1 {
			prompt = l[start : start+end]
		}
	}
	return strings.TrimSpace(prompt)
}

// readNewTranscriptPrompts returns prompts appended to the transcript since the recorded offset,
// with the byte offset of each prompt's line. Only complete (newline-terminated) lines are consumed
// so a half-written line is picked up on the next poll. A path never seen before starts at 0: it is
// a conversation that began after the tailer's baseline.
func readNewTranscriptPrompts(path string, offsets map[string]int64) (prompts []string, spans []int64, next int64, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, 0, false
	}
	start := offsets[path]
	if info.Size() < start {
		start = 0 // truncated or rotated
	}
	if info.Size() == start {
		return nil, nil, start, true
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, nil, 0, false
	}
	data, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return nil, nil, 0, false
	}
	next = start
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			break
		}
		if p := parsePromptLine(string(data[:nl])); p != "" {
			prompts = append(prompts, p)
			spans = append(spans, next)
		}
		next += int64(nl + 1)
		data = data[nl+1:]
	}
	return prompts, spans, next, true
}

// baselineTranscripts records the current end of every existing transcript so history is never
// replayed into a new session. A transcript touched in the last minute is the conversation that
// triggered this session, so its final prompt (only) is reported through report if not already claimed.
func baselineTranscripts(roots []string, offsets map[string]int64, now time.Time, report func(prompt string)) {
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			for _, p := range transcriptCandidates(root, e.Name()) {
				info, err := os.Stat(p)
				if err != nil {
					continue
				}
				offsets[p] = info.Size()
				if now.Sub(info.ModTime()) > time.Minute || report == nil {
					continue
				}
				prompts, spans, _, ok := readNewTranscriptPrompts(p, map[string]int64{})
				if !ok || len(prompts) == 0 {
					continue
				}
				claim := promptClaimKey(p, spans[len(spans)-1])
				if isPromptHashSent(claim) {
					continue
				}
				markPromptHashSent(claim)
				report(prompts[len(prompts)-1])
			}
		}
	}
}

// postTailedPrompt reports one transcript prompt to the control plane.
func postTailedPrompt(client *http.Client, sessionID, serverURL, conv string, offset int64, userReq string) {
	h := sha256.Sum256([]byte(userReq))
	payload := map[string]any{
		"session_id":             sessionID,
		"user_prompt":            userReq,
		"producer":               "antigravity-cli",
		"prompt_hash":            hex.EncodeToString(h[:]),
		"prompt_capture_enabled": true,
		"intent": map[string]any{
			"primary":            "INVESTIGATION",
			"confidence":         0.90,
			"classifier_version": "bap-edge-rules-v1",
			"source":             "antigravity-transcript-tail",
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	resp, err := client.Post(strings.TrimRight(serverURL, "/")+"/api/v1/sessions/prompt", "application/json", bytes.NewReader(data))
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
}

func extractPromptsFromTranscript(path string) []string {
	prompts, _, _, _ := readNewTranscriptPrompts(path, map[string]int64{})
	var results []string
	results = append(results, prompts...)
	return results
}


