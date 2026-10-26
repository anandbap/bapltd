package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"bap-edge/internal/httptransport"
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
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("LTD_SOURCE")), "antigravity") {
		return sessionID
	}
	if mcpDevOverrideActive() {
		fmt.Fprintln(os.Stderr, "[BAP DEV OVERRIDE ACTIVE] Antigravity self-enrollment skipped; this session is not governed or reported.")
		return sessionID
	}
	if sessionID == "" {
		sessionID = strings.TrimSpace(os.Getenv("BAP_SESSION_ID"))
	}
	if sessionID != "" && sessionIsLive(serverURL, sessionID) {
		startAntigravityPromptTail(sessionID, serverURL)
		return sessionID
	}
	targetID := sessionID
	ppid := os.Getppid()
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
	defer func() {
		promptTailMu.Lock()
		promptTailActive = false
		promptTailCancel = nil
		promptTailMu.Unlock()
	}()

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	searchRoots := []string{
		filepath.Join(home, ".gemini", "antigravity-cli", "brain"),
		filepath.Join(home, ".gemini", "antigravity", "brain"),
	}

	seenHashes := make(map[string]bool)
	client := httptransport.New(2 * time.Second)
	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
			cutoff := time.Now().Add(-15 * time.Minute)
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				candidatePaths := []string{
					filepath.Join(root, e.Name(), ".system_generated", "logs", "transcript.jsonl"),
					filepath.Join(root, e.Name(), "transcript.jsonl"),
				}
				for _, p := range candidatePaths {
					info, err := os.Stat(p)
					if err != nil || !info.ModTime().After(cutoff) {
						continue
					}
					prompts := extractPromptsFromTranscript(p)
					for _, userReq := range prompts {
						userReq = strings.TrimSpace(userReq)
						if userReq == "" {
							continue
						}
						h := sha256.Sum256([]byte(userReq))
						pHash := fmt.Sprintf("%x", h[:])
						if seenHashes[pHash] {
							continue
						}
						seenHashes[pHash] = true

						payload := map[string]any{
							"session_id":             sessionID,
							"user_prompt":            userReq,
							"producer":               "antigravity-cli",
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

func extractPromptsFromTranscript(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > 50 {
			lines = lines[1:]
		}
	}

	var results []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var prompt string
		if strings.Contains(l, "<USER_REQUEST>") {
			start := strings.Index(l, "<USER_REQUEST>") + len("<USER_REQUEST>")
			if end := strings.Index(l[start:], "</USER_REQUEST>"); end != -1 {
				prompt = l[start : start+end]
			}
		} else if strings.Contains(l, `"type":"USER_INPUT"`) || strings.Contains(l, `"type": "USER_INPUT"`) {
			var obj struct {
				Content string `json:"content"`
			}
			if json.Unmarshal([]byte(l), &obj) == nil && obj.Content != "" {
				raw := obj.Content
				if start := strings.Index(raw, "<USER_REQUEST>"); start != -1 {
					start += len("<USER_REQUEST>")
					if end := strings.Index(raw[start:], "</USER_REQUEST>"); end != -1 {
						prompt = raw[start : start+end]
					}
				} else {
					prompt = raw
				}
			}
		}
		prompt = strings.TrimSpace(prompt)
		if prompt != "" {
			results = append(results, prompt)
		}
	}
	return results
}


