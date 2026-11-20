package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/httptransport"
)

func sessionReportingPath(path string) bool {
	return path == "/api/v1/sessions/start" || path == "/api/v1/sessions/prompt" || path == "/api/v1/sessions/end"
}

// Share the hook's existing durable outbox format, adding destination/path
// binding for lifecycle reports. Stable body/turn identity survives retries.
func queueSessionReport(target string, payload any) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if !sessionReportingPath(parsed.Path) {
		return "", nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	raw, err = httptransport.CaptureLocalJSON(raw)
	if err != nil {
		return "", err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", err
	}
	var sid string
	if err := json.Unmarshal(fields["session_id"], &sid); err != nil || sid == "" {
		return "", fmt.Errorf("session report has no stable session identity")
	}
	envelope := map[string]any{"session_id": sid, "server_url": parsed.Scheme + "://" + parsed.Host, "endpoint": parsed.Path, "created_at": time.Now().UTC(), "body": json.RawMessage(raw)}
	body, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	dir := promptSpoolDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	id := strings.ReplaceAll(audit.GenerateEventID(), "/", "_")
	path := filepath.Join(dir, fmt.Sprintf("%020d-%s.json", time.Now().UnixNano(), id))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return path, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return path, err
	}
	return path, f.Close()
}

func removeDeliveredSessionReport(path string) {
	if path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "BAP reporting: acknowledged envelope retained for automatic cleanup: %v\n", err)
		}
	}
}
