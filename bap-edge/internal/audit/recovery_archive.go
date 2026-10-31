package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"bap-edge/internal/httptransport"
)

type recoveryRecord struct {
	Epoch string     `json:"epoch"`
	Entry AuditEntry `json:"entry"`
}
type recoveryCursor struct {
	Epoch  string `json:"epoch"`
	Offset int64  `json:"offset"`
}

var archiveLocks sync.Map

func archivePath(server, log string) string {
	sum := sha256.Sum256([]byte(strings.TrimRight(server, "/")))
	return fmt.Sprintf("%s.recovery-%x.jsonl", log, sum[:8])
}

func archiveAcknowledged(server, log string, entries []AuditEntry, epoch string) error {
	path := archivePath(server, log)
	value, _ := archiveLocks.LoadOrStore(path, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, entry := range entries {
		body, err := json.Marshal(recoveryRecord{Epoch: epoch, Entry: entry})
		if err != nil {
			return err
		}
		if _, err = f.Write(append(body, '\n')); err != nil {
			return err
		}
	}
	// Only remove the pending copy after its retained recovery copy is durable.
	return f.Sync()
}

var archiveReplayMu sync.Mutex

// One bounded background batch per flush. Current-epoch records are skipped;
// only a changed control-plane instance triggers historical backfill.
func replayRecoveryArchive(server, log string) (int, error) {
	epoch := httptransport.ControlPlaneEpoch(server)
	if epoch == "" || !archiveReplayMu.TryLock() {
		return 0, nil
	}
	defer archiveReplayMu.Unlock()
	path := archivePath(server, log)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var cursor recoveryCursor
	if raw, err := os.ReadFile(path + ".cursor"); err == nil {
		var saved recoveryCursor
		if json.Unmarshal(raw, &saved) == nil {
			cursor = saved
		}
	}
	if cursor.Epoch != epoch {
		cursor = recoveryCursor{Epoch: epoch}
	}
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if cursor.Offset < 0 || cursor.Offset > info.Size() {
		cursor.Offset = 0
	}
	if _, err = f.Seek(cursor.Offset, io.SeekStart); err != nil {
		return 0, err
	}
	reader := bufio.NewReader(f)
	var entries []AuditEntry
	for scanned := 0; scanned < 5000 && len(entries) < 50; scanned++ {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		var record recoveryRecord
		if err = json.Unmarshal(line, &record); err != nil {
			return 0, fmt.Errorf("invalid retained recovery record: %w", err)
		}
		cursor.Offset += int64(len(line))
		if record.Epoch != epoch {
			entry := record.Entry
			entry.FullCommand, entry.Arguments, entry.UserPrompt = defangWAF(entry.FullCommand), defangWAF(entry.Arguments), defangWAF(entry.UserPrompt)
			entries = append(entries, entry)
		}
	}
	if len(entries) > 0 {
		body, _ := json.Marshal(entries)
		req, err := http.NewRequest("POST", strings.TrimRight(server, "/")+"/api/v1/audit/ingest", bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return 0, err
		}
		var ack HandshakeAck
		err = json.NewDecoder(resp.Body).Decode(&ack)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || !ack.ChainValid || (ack.Ingested == 0 && ack.Status != "acknowledged") {
			return 0, fmt.Errorf("recovery backfill was not verified")
		}
		if ack.ServerEpoch != "" && ack.ServerEpoch != epoch {
			return 0, fmt.Errorf("control plane restarted during backfill")
		}
	}
	data, _ := json.Marshal(cursor)
	// A torn/missing cursor causes duplicate replay, not loss; EventID dedup handles it.
	if err = os.WriteFile(path+".cursor", data, 0600); err != nil {
		return 0, err
	}
	return len(entries), nil
}

func RecoveryArchiveBytes(server, log string) int64 {
	if info, err := os.Stat(archivePath(server, log)); err == nil {
		return info.Size()
	}
	return 0
}
