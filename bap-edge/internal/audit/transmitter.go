package audit

import (
	"bap-edge/internal/httptransport"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

var httpClient = httptransport.New(300 * time.Millisecond)

// HandshakeAck models the cryptographic acknowledgement returned by bapcontrolplane.
type HandshakeAck struct {
	Ingested    int    `json:"ingested"`
	ChainValid  bool   `json:"chain_valid"`
	ReceiptHash string `json:"receipt_hash,omitempty"`
	Status      string `json:"status,omitempty"`
}

// GenerateEventID generates a unique identifier for an audit entry.
func GenerateEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("edge-%d-%s", time.Now().UnixNano(), hex.EncodeToString(b))
}

// Transmit sends an AuditEntry to the central control plane with a clean handshake.
// If the server confirms ingestion (HTTP 200, Ingested > 0, ChainValid == true),
// the transmitted entry is safely removed locally from logPath, eliminating edge storage burden.
// If the server is offline or fails the handshake, the entry is safely preserved in logPath.
func Transmit(entry AuditEntry, serverURL string, logPath string) (bool, string, error) {
	if serverURL == "" || serverURL == "off" || serverURL == "none" {
		return false, "", nil
	}

	// 1. Filter out self-testing logs: keep them in local ltd-audit.jsonl for assertions, do not pollute central service
	if os.Getenv("BAP_TEST_MODE") == "1" || os.Getenv("LTD_TEST") == "1" || os.Getenv("BAP_ENV") == "test" {
		return false, "skipped_test_mode", nil
	}
	srcLower := strings.ToLower(entry.Source)
	if strings.Contains(srcLower, "test") || strings.Contains(srcLower, "pytest") || strings.Contains(srcLower, "selftest") {
		return false, "skipped_test_source", nil
	}
	cmdLower := strings.ToLower(entry.FullCommand)
	if strings.HasPrefix(cmdLower, "pytest") || strings.Contains(cmdLower, "test_leak.py") || strings.Contains(cmdLower, "go test") {
		return false, "skipped_test_command", nil
	}

	// Clean trailing slash
	serverURL = strings.TrimRight(serverURL, "/")
	ingestURL := serverURL + "/api/v1/audit/ingest"

	if entry.EventID == "" {
		entry.EventID = GenerateEventID()
	}

	// Payload expected by /api/v1/audit/ingest:
	payload := []map[string]any{
		{
			"event_id":      entry.EventID,
			"session_id":    entry.SessionID,
			"user_id":       entry.UserID,
			"user_email":    entry.UserEmail,
			"spiffe_id":     entry.SPIFFEID,
			"timestamp":     entry.Timestamp.UTC().Format(time.RFC3339),
			"source":        entry.Source,
			"user_prompt":   entry.UserPrompt,
			"client_pid":    entry.ClientPID,
			"executable":    entry.Executable,
			"arguments":     entry.Arguments,
			"full_command":  entry.FullCommand,
			"decision":      entry.Decision,
			"reason":        entry.Reason,
			"duration_ms":   entry.DurationMs,
			"exit_code":     entry.ExitCode,
			"previous_hash": entry.PreviousHash,
			"entry_hash":    entry.EntryHash,
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return false, "", err
	}

	req, err := http.NewRequest(http.MethodPost, ingestURL, bytes.NewReader(data))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, "offline", nil // server offline/unreachable: fail-secure, keep local entry
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("http_%d", resp.StatusCode), nil
	}

	// 2. Clean Handshake Verification:
	// Verify that the server successfully ingested the event and confirmed chain integrity
	var ack HandshakeAck
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return false, "invalid_handshake", err
	}

	if ack.Ingested <= 0 || !ack.ChainValid {
		return false, "unverified_handshake", fmt.Errorf("server handshake failed: ingested=%d, chain_valid=%v", ack.Ingested, ack.ChainValid)
	}

	// 3. Remove transmitted entry locally after clean handshake (unless explicit retention is requested)
	if os.Getenv("BAP_RETAIN_LOCAL") != "1" && logPath != "" && logPath != "off" && logPath != "none" {
		_ = RemoveEntry(entry.EventID, logPath)
	}

	return true, ack.ReceiptHash, nil
}

// FlushOfflineAudit reads un-ingested local audit entries and flushes them to the central control plane.
// Returns the count of successfully ingested entries.
func FlushOfflineAudit(serverURL string, logPath string) (int, error) {
	if serverURL == "" || serverURL == "off" || serverURL == "none" {
		return 0, nil
	}
	if logPath == "" {
		logPath = DefaultLogPath()
	}

	entries, err := ReadEntries(logPath)
	if err != nil || len(entries) == 0 {
		return 0, err
	}

	// Filter out test-mode entries to prevent polluting production control plane
	var toSend []AuditEntry
	for _, entry := range entries {
		srcLower := strings.ToLower(entry.Source)
		if strings.Contains(srcLower, "test") || strings.Contains(srcLower, "pytest") || strings.Contains(srcLower, "selftest") {
			continue
		}
		cmdLower := strings.ToLower(entry.FullCommand)
		if strings.HasPrefix(cmdLower, "pytest") || strings.Contains(cmdLower, "test_leak.py") || strings.Contains(cmdLower, "go test") {
			continue
		}
		toSend = append(toSend, entry)
	}

	if len(toSend) == 0 {
		return 0, nil
	}

	serverURL = strings.TrimRight(serverURL, "/")
	ingestURL := serverURL + "/api/v1/audit/ingest"

	var payload []map[string]any
	for _, entry := range toSend {
		if entry.EventID == "" {
			entry.EventID = GenerateEventID()
		}
		payload = append(payload, map[string]any{
			"event_id":      entry.EventID,
			"session_id":    entry.SessionID,
			"user_id":       entry.UserID,
			"user_email":    entry.UserEmail,
			"spiffe_id":     entry.SPIFFEID,
			"timestamp":     entry.Timestamp.UTC().Format(time.RFC3339),
			"source":        entry.Source,
			"user_prompt":   entry.UserPrompt,
			"client_pid":    entry.ClientPID,
			"executable":    entry.Executable,
			"arguments":     entry.Arguments,
			"full_command":  entry.FullCommand,
			"decision":      entry.Decision,
			"reason":        entry.Reason,
			"duration_ms":   entry.DurationMs,
			"exit_code":     entry.ExitCode,
			"previous_hash": entry.PreviousHash,
			"entry_hash":    entry.EntryHash,
		})
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest(http.MethodPost, ingestURL, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil // Server currently unreachable: fail-secure, keep local entries intact
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("ingest endpoint returned HTTP %d", resp.StatusCode)
	}

	var ack HandshakeAck
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return 0, fmt.Errorf("failed to decode server handshake: %w", err)
	}

	if ack.Ingested > 0 && ack.ChainValid {
		if os.Getenv("BAP_RETAIN_LOCAL") != "1" {
			for _, entry := range toSend {
				_ = RemoveEntry(entry.EventID, logPath)
			}
		}
		return ack.Ingested, nil
	}

	return 0, nil
}

