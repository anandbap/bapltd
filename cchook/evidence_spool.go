package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var fileHookEvidence struct {
	SessionID, AppID, Tool, Path, Command, UserPrompt string
	PID                                               int
}

func prepareHookEvidence(payload HookPayload, sessionID, appID string) {
	fileHookEvidence.SessionID, fileHookEvidence.AppID = sessionID, appID
	fileHookEvidence.Tool, fileHookEvidence.Path = payload.ToolName, payload.ToolInput.FilePath
	if fileHookEvidence.Path == "" {
		fileHookEvidence.Path = payload.ToolInput.Path
	}
	fileHookEvidence.Command = payload.ToolInput.Command
	if fileHookEvidence.Command == "" {
		fileHookEvidence.Command = payload.ToolInput.CommandLine
	}
	if fileHookEvidence.Command == "" {
		fileHookEvidence.Command = payload.ToolInput.Cmd
	}
	if fileHookEvidence.Command == "" && payload.ToolCall != nil && payload.ToolCall.Args != nil {
		if cmd, ok := payload.ToolCall.Args["CommandLine"].(string); ok {
			fileHookEvidence.Command = cmd
		}
	}
	fileHookEvidence.UserPrompt = payload.UserPrompt
	fileHookEvidence.PID = os.Getppid()
}

func hookStateDir() string {
	if dir := strings.TrimSpace(os.Getenv("BAP_STATE_DIR")); dir != "" {
		return dir
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		binPath := filepath.Join(home, "bin", ".bapstate")
		if fi, err := os.Stat(binPath); err == nil && fi.IsDir() {
			return binPath
		}
		if mkErr := os.MkdirAll(binPath, 0700); mkErr == nil {
			return binPath
		}
		return binPath
	}
	return filepath.Join(os.TempDir(), "bapstate")
}

func hookEvidenceDir() string {
	return filepath.Join(hookStateDir(), "hook-evidence")
}

// spoolFileHookDecision persists hook decisions (both file tools and denied shell commands)
// to disk for the local daemon, writes directly to audit.jsonl, and notifies the control plane.
func spoolFileHookDecision(decision, reason string) error {
	e := fileHookEvidence
	if e.SessionID == "" {
		return nil
	}
	// For commands that are allowed, the downstream bapedge exec broker check will independently record
	// and transmit the broker-layer audit evidence.
	if strings.EqualFold(decision, "allow") && e.Command != "" {
		return nil
	}

	executable := e.Tool
	fullCommand := ""
	if e.Command != "" {
		fullCommand = e.Command
		if executable == "" {
			parts := strings.Fields(e.Command)
			if len(parts) > 0 {
				executable = parts[0]
			}
		}
	} else if e.Path != "" {
		fullCommand = e.Tool + " " + e.Path
	} else {
		fullCommand = e.Tool
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	id := "hook-" + hex.EncodeToString(random[:])
	nowISO := time.Now().UTC().Format(time.RFC3339Nano)
	action := ""
	switch strings.ToLower(e.Tool) {
	case "read", "glob", "grep", "ls":
		action = "fs:file:read"
	case "write":
		action = "fs:file:write"
	case "edit", "notebookedit":
		action = "fs:file:edit"
	}
	data, err := json.Marshal(map[string]any{
		"event_id":           id,
		"session_id":         e.SessionID,
		"source":             e.AppID,
		"client_pid":         e.PID,
		"timestamp":          nowISO,
		"reporting_layer":    "hook",
		"executable":         executable,
		"full_command":       fullCommand,
		"decision":           decision,
		"reason":             reason,
		"canonical_action":   action,
		"canonical_resource": e.Path,
	})
	if err != nil {
		return err
	}
	data, err = MinimizeTelemetryJSON(data)
	if err != nil {
		return err
	}

	// 1. Spool atomic record for bapedge daemon to collect
	dir := hookEvidenceDir()
	if err := os.MkdirAll(dir, 0700); err == nil {
		tmp := filepath.Join(dir, id+".tmp")
		if f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); err == nil {
			_, _ = f.Write(data)
			_ = f.Sync()
			_ = f.Close()
			_ = os.Rename(tmp, filepath.Join(dir, id+".json"))
		}
	}

	// 2. Direct append to local audit.jsonl ledgers (fail-safe for standalone mode)
	stateDirs := []string{hookStateDir()}
	if fi, err := os.Stat(".bapstate"); err == nil && fi.IsDir() && hookStateDir() != ".bapstate" {
		stateDirs = append(stateDirs, ".bapstate")
	}
	for _, sDir := range stateDirs {
		auditFile := filepath.Join(sDir, "audit.jsonl")
		if f, err := os.OpenFile(auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
			_, _ = f.Write(append(data, '\n'))
			_ = f.Sync()
			_ = f.Close()
		}
	}

	// 3. Fast direct notification to Control Plane /api/activity/ingest
	serverURL := resolveServerURL()
	if serverURL != "" {
		outcome := "Success"
		actStatus := "working"
		if strings.EqualFold(decision, "deny") {
			outcome = "Blocked"
			actStatus = "blocked"
		}
		activityEvt := map[string]any{
			"timestamp":        nowISO,
			"session_id":       e.SessionID,
			"agent_type":       e.AppID,
			"application":      e.AppID,
			"action":           fullCommand,
			"tool":             e.Tool,
			"policy_decision":  strings.ToUpper(decision),
			"action_status":    actStatus,
			"outcome_category": outcome,
			"deviation_reason": reason,
			"trace_id":         id,
		}
		if actBody, err := json.Marshal(activityEvt); err == nil {
			go func() {
				client := &http.Client{Timeout: 800 * time.Millisecond}
				resp, err := client.Post(serverURL+"/api/activity/ingest", "application/json", bytes.NewReader(actBody))
				if err == nil && resp != nil {
					_ = resp.Body.Close()
				}
			}()
		}
	}

	return nil
}
