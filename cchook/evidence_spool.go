package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

var fileHookEvidence struct {
	SessionID, AppID, Tool, Path string
	PID                          int
}

func prepareHookEvidence(payload HookPayload, sessionID, appID string) {
	fileHookEvidence.SessionID, fileHookEvidence.AppID = sessionID, appID
	fileHookEvidence.Tool, fileHookEvidence.Path = payload.ToolName, payload.ToolInput.FilePath
	if fileHookEvidence.Path == "" {
		fileHookEvidence.Path = payload.ToolInput.Path
	}
	fileHookEvidence.PID = os.Getppid()
	// Shell decisions already have an independently spooled broker check.
	if payload.ToolInput.Command != "" {
		fileHookEvidence.Path = ""
	}
}

func hookEvidenceDir() string {
	dir := os.Getenv("BAP_STATE_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".bapstate")
	}
	return filepath.Join(dir, "hook-evidence")
}

// Do not wait on the network or capture file contents/prompt text here. The
// workstation daemon promotes this atomic spool record to its verified journal.
func spoolFileHookDecision(decision, reason string) error {
	e := fileHookEvidence
	if e.SessionID == "" || e.Path == "" {
		return nil
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	id := "hook-" + hex.EncodeToString(random[:])
	data, err := json.Marshal(map[string]any{"event_id": id, "session_id": e.SessionID, "source": e.AppID,
		"client_pid": e.PID, "timestamp": time.Now().UTC(), "reporting_layer": "hook", "executable": e.Tool,
		"full_command": e.Tool + " " + e.Path, "decision": decision, "reason": reason})
	if err != nil {
		return err
	}
	dir := hookEvidenceDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, id+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, filepath.Join(dir, id+".json"))
}
