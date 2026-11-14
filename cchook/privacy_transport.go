package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var telemetrySecret = regexp.MustCompile(`(?i)((?:token|secret|password|api[_-]?key|authorization|bearer)\s*[=: ]\s*)[^\s"']+`)

// Metadata is the default. Redacted content requires explicit operator opt-in; it may contain
// source code and is not a DLP guarantee. Apply on every retry, including old spooled records.
func MetadataOnly() bool { return os.Getenv("BAP_TELEMETRY_CONTENT") != "redacted" }

func telemetryContentPath(path string) bool {
	switch path {
	case "/api/v1/audit/ingest", "/api/v1/sessions/start", "/api/v1/sessions/resume",
		"/api/v1/sessions/prompt", "/api/v1/sessions/response", "/api/activity/ingest", "/api/v1/activity/ingest":
		return true
	}
	return false
}

func MinimizeTelemetryJSON(raw []byte) ([]byte, error) {
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
			if prompt, ok := node["user_prompt"].(string); ok && prompt != "" && node["prompt_hash"] == nil {
				sum := sha256.Sum256([]byte(prompt))
				node["prompt_hash"] = hex.EncodeToString(sum[:])
			}
			for key, child := range node {
				switch strings.ToLower(key) {
				case "user_prompt", "prompt", "prompt_text", "agent_response", "response", "full_command", "arguments", "command", "text", "content", "evidence", "description", "task_description", "error":
					if MetadataOnly() {
						delete(node, key)
						continue
					}
				case "prompt_captured", "prompt_capture_enabled", "captured":
					if MetadataOnly() {
						node[key] = false
						continue
					}
				case "reason":
					if MetadataOnly() {
						node[key] = "Details withheld by metadata capture policy"
						continue
					}
				}
				if text, ok := child.(string); ok {
					text = telemetrySecret.ReplaceAllString(text, "${1}[redacted]")
					if len(text) > 4096 {
						text = text[:4096] + "[truncated]"
					}
					node[key] = text
				} else {
					visit(child)
				}
			}
			if MetadataOnly() {
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
