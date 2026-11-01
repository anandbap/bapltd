package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var activeMCPPayload HookPayload

func mcpLabel(s string) string {
	if len(s) > 0 && len(s) <= 100 && !strings.HasPrefix(s, "eyJ") {
		ok := true
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.", c)) {
				ok = false
			}
		}
		if ok {
			return s
		}
	}
	sum := sha256.Sum256([]byte(s))
	return "asset-" + hex.EncodeToString(sum[:6])
}

// Native invocation evidence is observation only. No payload inputs, results,
// URLs, arguments, or environment values are copied into the discovery journal.
func spoolMCPObservation(payload HookPayload, outcome string) error {
	if !strings.HasPrefix(payload.ToolName, "mcp__") {
		return nil
	}
	parts := strings.SplitN(strings.TrimPrefix(payload.ToolName, "mcp__"), "__", 2)
	if len(parts) != 2 {
		return nil
	}
	session := resolveSessionID(payload)
	if session == "" || payload.ToolUseID == "" {
		return nil
	} // no invented correlation
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	run := hex.EncodeToString(b[:])
	now := time.Now().UTC()
	operation := sha256.Sum256([]byte(session + "\x00" + payload.ToolUseID))
	op := hex.EncodeToString(operation[:16])
	app := payload.AppID
	if app == "" {
		app = payload.Source
	}
	if app == "" {
		app = "claude-code"
	}
	asset := sha256.Sum256([]byte(app + "\x00" + payload.ToolName))
	report := map[string]any{"version": 1, "run_id": run, "epoch": 0, "started_at": now, "completed_at": now, "status": "complete", "scopes": []map[string]string{{"id": "native-mcp", "status": "complete"}}, "observations": []map[string]any{{"key": "call-" + hex.EncodeToString(asset[:16]), "scope": "native-mcp", "kind": "mcp_call", "name": mcpLabel(mcpLabel(parts[0]) + "." + mcpLabel(parts[1])), "client": mcpLabel(app), "evidence": "invocation", "observed_at": now, "operation_id": op, "outcome": outcome}}}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	root := filepath.Dir(hookEvidenceDir())
	dir := filepath.Join(root, "discovery", "pending")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".mcp-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	_ = f.Chmod(0600)
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(dir, run+".json"))
}
