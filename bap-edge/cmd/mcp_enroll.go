package cmd

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"bap-edge/internal/httptransport"
)

const maxMCPDevOverrideWindow = 12 * time.Hour

// mcpDevOverrideActive reports whether the human operator opened a time-boxed development window.
// Unlike the hook, it is read only from the environment of the process that launched the agent,
// never from workspace files, so skipping enrollment cannot be switched on by editing config.
func mcpDevOverrideActive() bool {
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
	if sessionIsLive(serverURL, sessionID) {
		return sessionID
	}
	ppid := os.Getppid()
	fresh := fmt.Sprintf("sess-antigravity-%d", ppid)
	if err := RunSessionStart([]string{
		"--server=" + serverURL,
		"--session-id=" + fresh,
		"--app-id=antigravity",
		fmt.Sprintf("--pid=%d", ppid),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[BAP] Antigravity self-enrollment failed: %v\n", err)
		return sessionID
	}
	os.Setenv("BAP_SESSION_ID", fresh)
	return fresh
}
