package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
)

// RunSessionTelemetry keeps enrollment credentials inside the broker. Launchers
// pass JSON through stdin, never bearer tokens through process arguments.
func RunSessionTelemetry(args []string) error {
	fs := flag.NewFlagSet("session-telemetry", flag.ContinueOnError)
	server := fs.String("server", "", "Control-plane URL")
	kind := fs.String("kind", "", "start, heartbeat, prompt, response or end")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*server = config.ReportingEndpoint(*server)
	if err := config.CheckReportingEnrollment(*server); err != nil {
		return err
	}
	switch *kind {
	case "start", "heartbeat", "prompt", "response", "end":
	default:
		return fmt.Errorf("unsupported session telemetry kind")
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, (1<<20)+1))
	if err != nil || len(body) > 1<<20 || !json.Valid(body) {
		return fmt.Errorf("valid JSON payload up to 1 MiB required on stdin")
	}
	client := httptransport.New(3 * time.Second)
	resp, err := client.Post(strings.TrimRight(*server, "/")+"/api/v1/sessions/"+*kind, "application/json", bytes.NewReader(body))
	if err != nil {
		if *kind == "prompt" {
			_ = retainPromptTelemetry(body)
		}
		return err
	}
	defer closeHeartbeatResponse(resp)
	response, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if *kind == "prompt" && (resp.StatusCode == 401 || resp.StatusCode == 404 || resp.StatusCode >= 500) {
		_ = retainPromptTelemetry(body)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status_code": resp.StatusCode, "body": string(response)})
}

func retainPromptTelemetry(body []byte) error {
	var meta struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(body, &meta); err != nil || meta.SessionID == "" {
		return fmt.Errorf("session_id required for retry")
	}
	envelope, _ := json.Marshal(map[string]any{"session_id": meta.SessionID, "body": json.RawMessage(body)})
	if err := os.MkdirAll(promptSpoolDir(), 0700); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	return os.WriteFile(filepath.Join(promptSpoolDir(), fmt.Sprintf("%x.json", sum)), envelope, 0600)
}
