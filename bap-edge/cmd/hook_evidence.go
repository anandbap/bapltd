package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"bap-edge/internal/audit"
	"bap-edge/internal/state"
)

// Drain a bounded batch, never a full unbounded directory read. A hook file is
// removed only after the shared journal has been synchronized to disk.
func collectHookEvidence() (int, error) {
	dir := filepath.Join(state.Dir(), "hook-evidence")
	f, err := os.Open(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	files, _ := f.ReadDir(64)
	n := 0
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, file.Name())
		info, err := file.Info()
		if err != nil || info.Size() > 64<<10 {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return n, err
		}
		var entry audit.AuditEntry
		if json.Unmarshal(data, &entry) != nil || entry.SessionID == "" || entry.EventID == "" || entry.ReportingLayer != "hook" {
			continue
		}
		if err := audit.Log(&entry, ""); err != nil {
			return n, err
		}
		if err := audit.SyncLog(""); err != nil {
			return n, err
		}
		if err := os.Remove(path); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
