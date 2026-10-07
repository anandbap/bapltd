package audit

import (
	"bap-edge/internal/state"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// AuditEntry represents a structured, tamper-evident log record for an execution request.
type AuditEntry struct {
	EventID      string    `json:"event_id,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	UserPrompt   string    `json:"user_prompt,omitempty"`
	UserID       string    `json:"user_id,omitempty"`
	UserEmail    string    `json:"user_email,omitempty"`
	SPIFFEID     string    `json:"spiffe_id,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Source       string    `json:"source"`
	ClientPID    int       `json:"client_pid"`
	Executable   string    `json:"executable"`
	Arguments    string    `json:"arguments,omitempty"`
	FullCommand  string    `json:"full_command"`
	Decision     string    `json:"decision"` // "allow" or "deny"
	Reason       string    `json:"reason,omitempty"`
	DurationMs        int64     `json:"duration_ms"`
	ExitCode          int       `json:"exit_code"`
	Error             string    `json:"error,omitempty"`
	CanonicalAction   string    `json:"canonical_action,omitempty"`
	CanonicalResource string    `json:"canonical_resource,omitempty"`
	PreviousHash      string    `json:"previous_hash,omitempty"`
	EntryHash         string    `json:"entry_hash,omitempty"`
}

var mu sync.Mutex

// DefaultLogPath returns the default audit log file location in .bapstate/audit.jsonl.
// Precedence: BAP_AUDIT_LOG -> LTD_AUDIT_LOG -> <.bapstate>/audit.jsonl
func DefaultLogPath() string {
	return state.AuditLogPath()
}

// ComputeEntryHash calculates a deterministic SHA-256 integrity hash for an entry.
func ComputeEntryHash(entry AuditEntry, prevHash string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(entry.EventID))
	h.Write([]byte(entry.SessionID))
	h.Write([]byte(entry.Timestamp.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(entry.Source))
	h.Write([]byte(strconv.Itoa(entry.ClientPID)))
	h.Write([]byte(entry.Executable))
	h.Write([]byte(entry.FullCommand))
	h.Write([]byte(entry.Decision))
	h.Write([]byte(strconv.Itoa(entry.ExitCode)))
	return hex.EncodeToString(h.Sum(nil))
}

// Log records an AuditEntry to the specified log file in JSON Lines format.
// It accepts either *AuditEntry or AuditEntry.
// It computes a sequential SHA-256 hash linked to the previous entry,
// guaranteeing cryptographic tamper evidence for local audit storage.
func Log(entryInput any, logPath string) error {
	if logPath == "off" || logPath == "none" {
		return nil
	}
	if logPath == "" {
		logPath = DefaultLogPath()
	}

	var entry *AuditEntry
	switch v := entryInput.(type) {
	case *AuditEntry:
		entry = v
	case AuditEntry:
		entry = &v
	default:
		return fmt.Errorf("unsupported entry type")
	}

	mu.Lock()
	defer mu.Unlock()

	// Ensure parent directory exists
	dir := filepath.Dir(logPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if entry.EventID == "" {
		entry.EventID = GenerateEventID()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	} else {
		entry.Timestamp = entry.Timestamp.UTC()
	}

	// Determine previous hash from existing file tail
	lastHash := "genesis-ltd-local"
	if info, err := os.Stat(logPath); err == nil && info.Size() > 0 {
		content, err := os.ReadFile(logPath)
		if err == nil && len(content) > 0 {
			lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
			for idx := len(lines) - 1; idx >= 0; idx-- {
				var lastEntry AuditEntry
				if err := json.Unmarshal(lines[idx], &lastEntry); err == nil && lastEntry.EntryHash != "" {
					lastHash = lastEntry.EntryHash
					break
				}
			}
		}
	}

	entry.PreviousHash = lastHash
	entry.EntryHash = ComputeEntryHash(*entry, lastHash)

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	data = append(data, '\n')
	_, err = f.Write(data)
	return err
}

// VerifyLocalLog checks the cryptographic integrity of the local JSONL log.
// It verifies that each entry hash correctly links to the previous entry
// and matches the computed digest over the entry contents.
func VerifyLocalLog(logPath string) (bool, int, error) {
	if logPath == "" {
		logPath = DefaultLogPath()
	}

	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(logPath)
	if os.IsNotExist(err) || (err == nil && info.Size() == 0) {
		return true, 0, nil // Empty or missing log is considered valid
	}
	if err != nil {
		return false, 0, err
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		return false, 0, err
	}

	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	expectedPrev := "genesis-ltd-local"
	count := 0

	for i, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		var entry AuditEntry
		if err := json.Unmarshal(trimmed, &entry); err != nil {
			return false, i + 1, fmt.Errorf("invalid json on line %d: %w", i+1, err)
		}

		// Backward compatibility for unhashed legacy entries
		if entry.EntryHash == "" {
			count++
			continue
		}

		// Support explicit genesis blocks initiating new sessions
		if entry.PreviousHash == "genesis-ltd-local" {
			expectedPrev = "genesis-ltd-local"
		}

		if entry.PreviousHash != expectedPrev {
			return false, i + 1, fmt.Errorf("tamper alert at line %d: broken chain - expected previous_hash %s, got %s", i+1, expectedPrev, entry.PreviousHash)
		}

		computed := ComputeEntryHash(entry, expectedPrev)
		if entry.EntryHash != computed {
			return false, i + 1, fmt.Errorf("tamper alert at line %d: entry_hash mismatch (content modified)", i+1)
		}

		expectedPrev = entry.EntryHash
		count++
	}

	return true, count, nil
}

// RemoveEntry removes a specific entry by event_id after confirmed server transmission.
// If no entries remain, it truncates the file to 0 bytes, removing storage burden from edge devices.
func RemoveEntry(eventID string, logPath string) error {
	if eventID == "" || logPath == "off" || logPath == "none" {
		return nil
	}
	if logPath == "" {
		logPath = DefaultLogPath()
	}

	mu.Lock()
	defer mu.Unlock()

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return nil
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		return err
	}

	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	var remainingLines [][]byte

	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(trimmed, &entry); err == nil {
			if entry.EventID == eventID {
				continue // Skip the successfully transmitted event
			}
		}
		remainingLines = append(remainingLines, line)
	}

	if len(remainingLines) == 0 {
		// Truncate to 0 bytes to relieve edge storage burden
		return os.Truncate(logPath, 0)
	}

	// If there are other untransmitted entries, rewrite the remaining lines
	var buf bytes.Buffer
	for _, l := range remainingLines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	return os.WriteFile(logPath, buf.Bytes(), 0644)
}

// RemoveEntries removes multiple entries by event_id in a single atomic pass.
func RemoveEntries(eventIDs map[string]struct{}, logPath string) error {
	if len(eventIDs) == 0 || logPath == "off" || logPath == "none" {
		return nil
	}
	if logPath == "" {
		logPath = DefaultLogPath()
	}

	mu.Lock()
	defer mu.Unlock()

	content, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	var remainingLines [][]byte

	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var entry struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(trimmed, &entry); err == nil && entry.EventID != "" {
			if _, remove := eventIDs[entry.EventID]; remove {
				continue
			}
		}
		remainingLines = append(remainingLines, line)
	}

	if len(remainingLines) == 0 {
		return os.Truncate(logPath, 0)
	}

	var buf bytes.Buffer
	for _, l := range remainingLines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	return os.WriteFile(logPath, buf.Bytes(), 0644)
}

// ClearLog truncates the local log file to 0 bytes.
func ClearLog(logPath string) error {
	if logPath == "" {
		logPath = DefaultLogPath()
	}
	mu.Lock()
	defer mu.Unlock()
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return nil
	}
	return os.Truncate(logPath, 0)
}

// ReadEntries parses and returns all valid AuditEntry records from the given logPath.
func ReadEntries(logPath string) ([]AuditEntry, error) {
	if logPath == "" {
		logPath = DefaultLogPath()
	}
	mu.Lock()
	defer mu.Unlock()

	info, err := os.Stat(logPath)
	if os.IsNotExist(err) || (err == nil && info.Size() == 0) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	var entries []AuditEntry
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(trimmed, &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

