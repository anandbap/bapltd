package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var onboardingMarker = regexp.MustCompile(`\bBAP-ONBOARDING-([a-f0-9]{32})\b`)

// Best-effort metadata health signal, not a prompt/tool payload or an authority
// receipt. The durable audit/prompt spools remain the evidence delivery path.
func recordNativeCallback(payload HookPayload) {
	event := payload.HookEventName
	switch event {
	case "SessionStart", "UserPromptSubmit", "UserPrompt", "PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop", "SessionEnd", "SessionStop":
	default:
		return
	}
	app := payload.AppID
	if app == "" {
		app = payload.Source
	}
	if app == "" {
		app = "claude-code"
	}
	switch strings.ToLower(app) {
	case "claude", "claude-code":
		app = "claude-code"
	case "codex", "codex-lifecycle-hook":
		app = "codex"
	case "antigravity", "copilot", "cursor", "gemini":
	default:
		return
	}
	dir := filepath.Join(filepath.Dir(hookEvidenceDir()), "reporting-health")
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	record := map[string]any{"app": app, "event": event, "observed_at": time.Now().UTC(), "source": "native_callback"}
	if sid := resolveSessionID(payload); sid != "" {
		sum := sha256.Sum256([]byte(sid))
		record["session_reference"] = hex.EncodeToString(sum[:])
	}
	if match := onboardingMarker.FindStringSubmatch(payload.UserPrompt); len(match) == 2 {
		record["probe_id"] = match[1]
	}
	body, _ := json.Marshal(record)
	f, err := os.CreateTemp(dir, ".callback-")
	if err != nil {
		return
	}
	name := f.Name()
	defer os.Remove(name)
	_ = f.Chmod(0600)
	_, err = f.Write(body)
	closeErr := f.Close()
	if err == nil && closeErr == nil {
		_ = os.Rename(name, filepath.Join(dir, app+"-"+event+".json"))
	}
}
