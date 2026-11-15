package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var telemetrySecret = regexp.MustCompile(`(?i)((?:token|secret|password|api[_-]?key|authorization|bearer)\s*[=: ]\s*)[^\s"']+`)

// Metadata is the default. Redacted content requires explicit operator opt-in; it may contain
// source code and is not a DLP guarantee. Apply on every retry, including old spooled records.
func MetadataOnly() bool { return os.Getenv("BAP_TELEMETRY_CONTENT") != "redacted" }

// Prompt capture modes, owned by the control plane administrator.
const (
	promptCaptureRequired       = "required"        // default: always reported, no local override
	promptCaptureUserControlled = "user_controlled" // admin lets users opt out via env / config
	promptCaptureOff            = "off"             // admin withholds prompt text
)

var (
	adminPromptModeOnce sync.Once
	adminPromptModeVal  string
	// adminPromptCaptureModeFn is replaceable in tests.
	adminPromptCaptureModeFn = queryAdminPromptCaptureMode
)

// adminPromptCaptureMode returns the administrator's prompt-capture mode. It comes only from the
// bapedge broker, which resolves it from the Ed25519-verified policy bundle; the hook never reads
// an editable file for it. Anything unavailable or unexpected yields the default (required), so a
// local edit or a missing binary can never switch prompt reporting off.
func adminPromptCaptureMode() string {
	adminPromptModeOnce.Do(func() { adminPromptModeVal = adminPromptCaptureModeFn() })
	return adminPromptModeVal
}

func queryAdminPromptCaptureMode() string {
	bin := findBinary("bapedge.exe")
	if _, err := os.Stat(bin); err != nil {
		bin = findBinary("bapedge")
	}
	if _, err := os.Stat(bin); err != nil {
		if p, lerr := exec.LookPath("bapedge"); lerr == nil {
			bin = p
		} else {
			return promptCaptureRequired
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "policy-setting", "prompt-capture").Output()
	if err != nil {
		return promptCaptureRequired
	}
	switch strings.TrimSpace(string(out)) {
	case promptCaptureOff:
		return promptCaptureOff
	case promptCaptureUserControlled:
		return promptCaptureUserControlled
	}
	return promptCaptureRequired
}

// PromptContentAllowed reports whether prompt text may leave this machine: always, unless the
// administrator turned prompt reporting off, or allowed users to opt out and this user did.
func PromptContentAllowed() bool { return shouldCaptureUserPrompt() }

func telemetryContentPath(path string) bool {
	switch path {
	case "/api/v1/audit/ingest", "/api/v1/sessions/start", "/api/v1/sessions/resume",
		"/api/v1/sessions/prompt", "/api/v1/sessions/response", "/api/activity/ingest", "/api/v1/activity/ingest":
		return true
	}
	return false
}

func MinimizeTelemetryJSON(raw []byte) ([]byte, error) {
	return filterEvidenceJSON(raw, false)
}

// CaptureLocalJSON retains local evidence independently of outbound telemetry policy.
// Credential redaction still applies, but local command/reason text is never dropped.
func CaptureLocalJSON(raw []byte) ([]byte, error) {
	return filterEvidenceJSON(raw, true)
}

func filterEvidenceJSON(raw []byte, local bool) ([]byte, error) {
	metadataOnly := !local && MetadataOnly()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	var visit func(any)
	visit = func(v any) {
		switch node := v.(type) {
		case []any:
			for _, child := range node {
				visit(child)
			}
		case map[string]any:
			// Retain correlation without retaining command content. Do this before
			// metadata minimization, and preserve it when retrying a spooled event.
			if command, ok := node["full_command"].(string); ok && command != "" && node["content_hash"] == nil {
				sum := sha256.Sum256([]byte(command))
				node["content_hash"] = hex.EncodeToString(sum[:])
			}
			if prompt, ok := node["user_prompt"].(string); ok && prompt != "" && node["prompt_hash"] == nil {
				sum := sha256.Sum256([]byte(prompt))
				node["prompt_hash"] = hex.EncodeToString(sum[:])
			}
			for key, child := range node {
				switch strings.ToLower(key) {
				case "token", "secret", "password", "api_key", "api-key", "apikey", "authorization", "access_token", "refresh_token":
					node[key] = "[redacted]"
					continue
				case "user_prompt", "prompt", "prompt_text":
					// Prompt text follows the administrator's prompt-capture mode, not the generic
					// content setting below.
					if !local && !PromptContentAllowed() {
						delete(node, key)
						continue
					}
				case "agent_response", "response", "full_command", "arguments", "command", "text", "content", "evidence", "description", "task_description", "error", "action", "deviation_reason", "tool_input", "input", "args", "parameters":
					if metadataOnly {
						delete(node, key)
						continue
					}
				case "prompt_captured", "prompt_capture_enabled":
					if !local && !PromptContentAllowed() {
						node[key] = false
						continue
					}
				case "captured":
					if metadataOnly {
						node[key] = false
						continue
					}
				case "reason":
					if metadataOnly {
						node[key] = "Details withheld by metadata capture policy"
						continue
					}
				}
				if text, ok := child.(string); ok {
					text = telemetrySecret.ReplaceAllString(text, "${1}[redacted]")
					if !local && len(text) > 4096 {
						text = text[:4096] + "[truncated]"
					}
					node[key] = text
				} else {
					visit(child)
				}
			}
			if metadataOnly {
				node["telemetry_content"] = "metadata"
			}
		}
	}
	visit(value)
	return json.Marshal(value)
}

func minimizeTelemetryRequest(req *http.Request) (*http.Request, error) {
	if req.Method != "POST" || req.Body == nil || !telemetryContentPath(req.URL.Path) {
		return req, nil
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, (4<<20)+1))
	_ = req.Body.Close()
	if err != nil || len(raw) > 4<<20 {
		return nil, fmt.Errorf("telemetry privacy filter: invalid or oversized body")
	}
	cleaned, err := MinimizeTelemetryJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("telemetry privacy filter: invalid JSON")
	}
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(cleaned))
	clone.ContentLength = int64(len(cleaned))
	clone.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(cleaned)), nil }
	return clone, nil
}
