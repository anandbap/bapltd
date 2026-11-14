package audit

import (
	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	httpClient = httptransport.New(1500 * time.Millisecond)

	offlineMux             sync.Mutex
	serverKnownOffline     bool
	lastServerOfflineCheck time.Time
	offlineBackoffDuration = 30 * time.Second
	// A watcher, daemon and explicit sync can flush the same spool concurrently.
	// Serialize snapshots and acknowledgements so a second flush sees the updated
	// ledger rather than uploading the same backlog again.
	flushMu sync.Mutex
)

var (
	wafPipeCurl = regexp.MustCompile(`(?i)\|\s*curl\s+http`)
	wafPipeWget = regexp.MustCompile(`(?i)\|\s*wget\s+http`)
)

// defangWAF prevents edge WAF false-positives (like Cloudflare/Render OWASP rules)
// from blocking audit events containing shell pipes or SSRF probe strings.
func defangWAF(s string) string {
	if s == "" {
		return s
	}
	s = wafPipeCurl.ReplaceAllString(s, "| [curl] http")
	s = wafPipeWget.ReplaceAllString(s, "| [wget] http")
	return s
}

// HandshakeAck models the cryptographic acknowledgement returned by bapcontrolplane.
type HandshakeAck struct {
	Durable     bool   `json:"durable"`
	ServerEpoch string `json:"server_epoch"`
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

// Test-mode environment flags may isolate an unenrolled development fixture.
// They must not suppress reporting on an enrolled or administrator-locked host.
func isolatedTestCollection() bool {
	requested := os.Getenv("BAP_TEST_MODE") == "1" || os.Getenv("LTD_TEST") == "1" || os.Getenv("BAP_ENV") == "test"
	return requested && config.EnrolledControlPlaneURL() == "" && !config.ResolveEndpoints().Locked
}

// Transmit sends an AuditEntry to the central control plane with a clean handshake.
// If the server confirms ingestion (HTTP 200, Ingested > 0, ChainValid == true),
// the transmitted entry is safely removed locally from logPath, eliminating edge storage burden.
// If the server is offline or fails the handshake, the entry is safely preserved in logPath.
func Transmit(entry AuditEntry, serverURL string, logPath string) (bool, string, error) {
	serverURL = config.ReportingEndpoint(serverURL)
	if err := config.CheckReportingEnrollment(serverURL); err != nil {
		return false, "enrollment_destination_mismatch", err
	}
	if serverURL == "" || serverURL == "off" || serverURL == "none" {
		return false, "", nil
	}

	// 1. Filter out self-testing logs: keep them in local ltd-audit.jsonl for assertions, do not pollute central service
	if isolatedTestCollection() {
		return false, "skipped_test_mode", nil
	}

	offlineMux.Lock()
	if serverKnownOffline && time.Since(lastServerOfflineCheck) < offlineBackoffDuration {
		offlineMux.Unlock()
		return false, "offline", nil
	}
	offlineMux.Unlock()

	// Clean trailing slash
	serverURL = strings.TrimRight(serverURL, "/")
	ingestURL := serverURL + "/api/v1/audit/ingest"

	if entry.EventID == "" {
		entry.EventID = GenerateEventID()
	}

	// Payload expected by /api/v1/audit/ingest:
	payload := []map[string]any{
		{
			"event_id":           entry.EventID,
			"canonical_action":   entry.CanonicalAction,
			"canonical_resource": entry.CanonicalResource,
			"prompt_hash":        entry.PromptHash,
			"reporting_layer":    entry.ReportingLayer,
			"evidence_grade":     entry.EvidenceGrade,
			"turn_id":            entry.TurnID,
			"session_id":         entry.SessionID,
			"user_id":            entry.UserID,
			"user_email":         entry.UserEmail,
			"spiffe_id":          entry.SPIFFEID,
			"timestamp":          entry.Timestamp.UTC().Format(time.RFC3339Nano),
			"source":             entry.Source,
			"user_prompt":        defangWAF(entry.UserPrompt),
			"client_pid":         entry.ClientPID,
			"executable":         entry.Executable,
			"arguments":          defangWAF(entry.Arguments),
			"full_command":       defangWAF(entry.FullCommand),
			"decision":           entry.Decision,
			"reason":             entry.Reason,
			"duration_ms":        entry.DurationMs,
			"exit_code":          entry.ExitCode,
			"content_hash":       entry.ContentHash,
			"previous_hash":      entry.PreviousHash,
			"entry_hash":         entry.EntryHash,
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
		offlineMux.Lock()
		serverKnownOffline = true
		lastServerOfflineCheck = time.Now()
		offlineMux.Unlock()
		return false, "offline", nil // server offline/unreachable: fail-secure, keep local entry
	}
	defer resp.Body.Close()

	offlineMux.Lock()
	serverKnownOffline = false
	offlineMux.Unlock()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("http_%d", resp.StatusCode), nil
	}

	// 2. Clean Handshake Verification:
	// Verify that the server successfully ingested the event and confirmed chain integrity
	var ack HandshakeAck
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return false, "invalid_handshake", err
	}

	if !ack.ChainValid || (ack.Ingested <= 0 && ack.Status != "acknowledged") {
		return false, "unverified_handshake", fmt.Errorf("server handshake failed: ingested=%d, chain_valid=%v", ack.Ingested, ack.ChainValid)
	}

	// 3. Remove transmitted entry locally after clean handshake (unless explicit retention is requested)
	if os.Getenv("BAP_RETAIN_LOCAL") != "1" && logPath != "" && logPath != "off" && logPath != "none" {
		if !ack.Durable {
			if err := archiveAcknowledged(serverURL, logPath, []AuditEntry{entry}, ack.ServerEpoch); err != nil {
				return false, "local_recovery_failed", err
			}
		}
		_ = RemoveEntry(entry.EventID, logPath)
	}

	return true, ack.ReceiptHash, nil
}

// FlushOfflineAudit reads un-ingested local audit entries and flushes them to the central control plane in batches.
// Returns the count of successfully flushed entries.
func FlushOfflineAudit(serverURL string, logPath string) (int, error) {
	flushMu.Lock()
	defer flushMu.Unlock()
	serverURL = config.ReportingEndpoint(serverURL)
	if err := config.CheckReportingEnrollment(serverURL); err != nil {
		return 0, err
	}
	if serverURL == "" || serverURL == "off" || serverURL == "none" {
		return 0, nil
	}

	if logPath == "" {
		logPath = DefaultLogPath()
	}

	entries, err := ReadEntries(logPath)
	if err != nil {
		return 0, err
	}

	// Explicit test mode isolates a synthetic run; command/source names never
	// distinguish synthetic activity from real engineering work. Keep all queued
	// evidence intact until an authenticated, verified acknowledgment.
	if isolatedTestCollection() {
		return 0, nil
	}
	toSend := entries

	if len(toSend) == 0 {
		return replayRecoveryArchive(serverURL, logPath)
	}

	serverURL = strings.TrimRight(serverURL, "/")
	ingestURL := serverURL + "/api/v1/audit/ingest"

	totalFlushed := 0
	batchSize := 50

	for i := 0; i < len(toSend); i += batchSize {
		end := i + batchSize
		if end > len(toSend) {
			end = len(toSend)
		}
		batch := toSend[i:end]

		var payload []map[string]any
		batchIDs := make(map[string]struct{}, len(batch))
		for _, entry := range batch {
			if entry.EventID == "" {
				entry.EventID = GenerateEventID()
			}
			batchIDs[entry.EventID] = struct{}{}
			payload = append(payload, map[string]any{
				"event_id":           entry.EventID,
				"canonical_action":   entry.CanonicalAction,
				"canonical_resource": entry.CanonicalResource,
				"prompt_hash":        entry.PromptHash,
				"reporting_layer":    entry.ReportingLayer,
				"evidence_grade":     entry.EvidenceGrade,
				"turn_id":            entry.TurnID,
				"session_id":         entry.SessionID,
				"user_id":            entry.UserID,
				"user_email":         entry.UserEmail,
				"spiffe_id":          entry.SPIFFEID,
				"timestamp":          entry.Timestamp.UTC().Format(time.RFC3339Nano),
				"source":             entry.Source,
				"user_prompt":        defangWAF(entry.UserPrompt),
				"client_pid":         entry.ClientPID,
				"executable":         entry.Executable,
				"arguments":          defangWAF(entry.Arguments),
				"full_command":       defangWAF(entry.FullCommand),
				"decision":           entry.Decision,
				"reason":             entry.Reason,
				"duration_ms":        entry.DurationMs,
				"exit_code":          entry.ExitCode,
				"content_hash":       entry.ContentHash,
				"previous_hash":      entry.PreviousHash,
				"entry_hash":         entry.EntryHash,
			})
		}

		data, err := json.Marshal(payload)
		if err != nil {
			return totalFlushed, err
		}

		req, err := http.NewRequest(http.MethodPost, ingestURL, bytes.NewReader(data))
		if err != nil {
			return totalFlushed, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			// Network error or timeout: fail-secure, stop batching and keep remaining entries
			return totalFlushed, fmt.Errorf("audit upload failed: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			var ack HandshakeAck
			err = json.NewDecoder(resp.Body).Decode(&ack)
			resp.Body.Close()
			if err != nil {
				return totalFlushed, fmt.Errorf("failed to decode server handshake: %w", err)
			}

			// Acknowledged by central control plane (either newly ingested or duplicate reconciled)
			if ack.ChainValid && (ack.Status == "acknowledged" || ack.Ingested > 0) {
				if os.Getenv("BAP_RETAIN_LOCAL") != "1" {
					if !ack.Durable {
						if err := archiveAcknowledged(serverURL, logPath, batch, ack.ServerEpoch); err != nil {
							return totalFlushed, err
						}
					}
					if err := RemoveEntries(batchIDs, logPath); err != nil {
						return totalFlushed, fmt.Errorf("remove acknowledged audit entries: %w", err)
					}
				}
				totalFlushed += len(batchIDs)
			} else {
				return totalFlushed, fmt.Errorf("unverified audit acknowledgement: chain_valid=%v", ack.ChainValid)
			}
		} else {
			resp.Body.Close()
			return totalFlushed, fmt.Errorf("ingest endpoint returned HTTP %d", resp.StatusCode)
		}
	}

	replayed, err := replayRecoveryArchive(serverURL, logPath)
	return totalFlushed + replayed, err
}
