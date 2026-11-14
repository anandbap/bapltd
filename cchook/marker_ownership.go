package main

import (
	"encoding/json"
	"os"
)

// removeOwnedMarker deletes a session marker file only if it still belongs to the session that is
// ending. Several markers are shared by every Claude session on one agent process (pid-<PID>.json,
// session.json, .bap-session.json) and are overwritten by whichever session started last. An older
// session ending or timing out must not delete a marker that now names a newer session, or the newer
// session loses its identity and heartbeat and is reaped as idle.
//
// A marker that is missing, unreadable, corrupt or carries no session id is treated as unowned and
// removed. A marker naming a different session is left alone, including when sessionID is empty.
func removeOwnedMarker(path, sessionID string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var info struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(data, &info) == nil && info.SessionID != "" && info.SessionID != sessionID {
		return
	}
	_ = os.Remove(path)
}
