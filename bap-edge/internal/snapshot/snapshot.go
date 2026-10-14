package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/state"
)

// FileSnapshot records the pre-execution state and hash of a modified file.
type FileSnapshot struct {
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	Existed      bool   `json:"existed"`
}

// CheckpointManifest represents an atomic snapshot checkpoint for a command or mutating action.
type CheckpointManifest struct {
	CheckpointID string         `json:"checkpoint_id"`
	SessionID    string         `json:"session_id"`
	Command      string         `json:"command"`
	Timestamp    time.Time      `json:"timestamp"`
	ReceiptID    string         `json:"receipt_id,omitempty"`
	Files        []FileSnapshot `json:"files"`
}

// RollbackResult reports the outcome of a rollback operation.
type RollbackResult struct {
	CheckpointID   string   `json:"checkpoint_id"`
	SessionID      string   `json:"session_id"`
	RestoredFiles  []string `json:"restored_files"`
	RemovedFiles   []string `json:"removed_files"`
	VerifiedHashes []string `json:"verified_hashes"`
}

// SnapshotsBaseDir returns the snapshots directory in .bapstate/snapshots.
func SnapshotsBaseDir() string {
	return filepath.Join(state.Dir(), "snapshots")
}

func fileSHA256(filePath string) (string, int64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// DetectTargetFiles extracts potential file modification paths from command arguments and redirections.
func DetectTargetFiles(cmdStr string) []string {
	var targets []string
	tokens := strings.Fields(cmdStr)
	for i, t := range tokens {
		// Detect redirection targets: > file, >> file, >file, >>file
		if t == ">" || t == ">>" {
			if i+1 < len(tokens) {
				targets = append(targets, cleanFilePath(tokens[i+1]))
			}
		} else if strings.HasPrefix(t, ">>") && len(t) > 2 {
			targets = append(targets, cleanFilePath(t[2:]))
		} else if strings.HasPrefix(t, ">") && len(t) > 1 {
			targets = append(targets, cleanFilePath(t[1:]))
		}
	}
	return deduplicate(targets)
}

func cleanFilePath(p string) string {
	trimmed := strings.Trim(p, "\"'` \t")
	return filepath.Clean(trimmed)
}

func deduplicate(list []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, item := range list {
		if item != "" && !seen[item] {
			seen[item] = true
			res = append(res, item)
		}
	}
	return res
}

// CreateCheckpoint snapshots the specified files (or detected command targets) before mutation.
func CreateCheckpoint(sessionID, command string, explicitFiles []string) (*CheckpointManifest, error) {
	if sessionID == "" {
		sessionID = "default"
	}

	targets := explicitFiles
	if len(targets) == 0 {
		targets = DetectTargetFiles(command)
	}
	if len(targets) == 0 {
		return nil, nil // No mutating targets identified
	}

	ts := time.Now().UTC()
	ckptID := fmt.Sprintf("ckpt-%d-%x", ts.Unix(), ts.Nanosecond()%0xffff)

	ckptDir := filepath.Join(SnapshotsBaseDir(), sessionID, ckptID)
	if err := os.MkdirAll(ckptDir, 0755); err != nil {
		return nil, err
	}

	var snapshots []FileSnapshot
	for _, target := range targets {
		absPath, err := filepath.Abs(target)
		if err != nil {
			absPath = target
		}

		info, statErr := os.Stat(absPath)
		if statErr == nil && !info.IsDir() {
			hash, size, err := fileSHA256(absPath)
			if err != nil {
				continue
			}
			pathSum := sha256.Sum256([]byte(absPath))
			backupFileName := fmt.Sprintf("%x_%s", pathSum[:8], filepath.Base(absPath))
			backupPath := filepath.Join(ckptDir, backupFileName)

			// Copy source file to backup
			srcF, err := os.Open(absPath)
			if err == nil {
				dstF, err := os.Create(backupPath)
				if err == nil {
					_, _ = io.Copy(dstF, srcF)
					dstF.Close()
				}
				srcF.Close()
			}

			snapshots = append(snapshots, FileSnapshot{
				OriginalPath: absPath,
				BackupPath:   backupPath,
				SHA256:       hash,
				SizeBytes:    size,
				Existed:      true,
			})
		} else if os.IsNotExist(statErr) {
			snapshots = append(snapshots, FileSnapshot{
				OriginalPath: absPath,
				BackupPath:   "",
				SHA256:       "",
				SizeBytes:    0,
				Existed:      false,
			})
		}
	}

	if len(snapshots) == 0 {
		_ = os.RemoveAll(ckptDir)
		return nil, nil
	}

	manifest := &CheckpointManifest{
		CheckpointID: ckptID,
		SessionID:    sessionID,
		Command:      command,
		Timestamp:    ts,
		Files:        snapshots,
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestFile := filepath.Join(ckptDir, "manifest.json")
	if err := os.WriteFile(manifestFile, manifestData, 0644); err != nil {
		return nil, err
	}

	// Update session checkpoints index
	updateSessionIndex(sessionID, manifest)

	return manifest, nil
}

func updateSessionIndex(sessionID string, manifest *CheckpointManifest) {
	indexFile := filepath.Join(SnapshotsBaseDir(), sessionID, "index.json")
	var history []*CheckpointManifest
	if data, err := os.ReadFile(indexFile); err == nil {
		_ = json.Unmarshal(data, &history)
	}
	history = append(history, manifest)
	if data, err := json.MarshalIndent(history, "", "  "); err == nil {
		_ = os.WriteFile(indexFile, data, 0644)
	}
}

// ListCheckpoints returns all saved checkpoints for a session.
func ListCheckpoints(sessionID string) ([]*CheckpointManifest, error) {
	if sessionID == "" {
		sessionID = "default"
	}
	indexFile := filepath.Join(SnapshotsBaseDir(), sessionID, "index.json")
	var history []*CheckpointManifest
	data, err := os.ReadFile(indexFile)
	if err != nil {
		return []*CheckpointManifest{}, nil
	}
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, err
	}
	return history, nil
}

// Rollback restores files from a checkpoint to their exact pre-execution state.
func Rollback(sessionID, checkpointID string, filterFile string) (*RollbackResult, error) {
	if sessionID == "" {
		sessionID = "default"
	}

	checkpoints, err := ListCheckpoints(sessionID)
	if err != nil {
		return nil, err
	}
	if len(checkpoints) == 0 {
		return nil, fmt.Errorf("no checkpoints found for session %q", sessionID)
	}

	var targetCkpt *CheckpointManifest
	if checkpointID != "" {
		for _, c := range checkpoints {
			if c.CheckpointID == checkpointID {
				targetCkpt = c
				break
			}
		}
		if targetCkpt == nil {
			return nil, fmt.Errorf("checkpoint %q not found in session %q", checkpointID, sessionID)
		}
	} else {
		// Default to latest checkpoint
		targetCkpt = checkpoints[len(checkpoints)-1]
	}

	res := &RollbackResult{
		CheckpointID: targetCkpt.CheckpointID,
		SessionID:    sessionID,
	}

	for _, snap := range targetCkpt.Files {
		if filterFile != "" {
			absFilter, _ := filepath.Abs(filterFile)
			if snap.OriginalPath != absFilter && filepath.Base(snap.OriginalPath) != filepath.Base(filterFile) {
				continue
			}
		}

		if snap.Existed {
			// Restore from backup
			src, err := os.Open(snap.BackupPath)
			if err != nil {
				return nil, fmt.Errorf("failed opening backup file %q: %v", snap.BackupPath, err)
			}
			dst, err := os.Create(snap.OriginalPath)
			if err != nil {
				src.Close()
				return nil, fmt.Errorf("failed writing restored file %q: %v", snap.OriginalPath, err)
			}
			_, _ = io.Copy(dst, src)
			src.Close()
			dst.Close()

			// Verify restored hash
			restoredHash, _, err := fileSHA256(snap.OriginalPath)
			if err != nil || restoredHash != snap.SHA256 {
				return nil, fmt.Errorf("cryptographic verification failed after restoring %q: expected %s, got %s", snap.OriginalPath, snap.SHA256, restoredHash)
			}

			res.RestoredFiles = append(res.RestoredFiles, snap.OriginalPath)
			res.VerifiedHashes = append(res.VerifiedHashes, fmt.Sprintf("%s: sha256:%s", filepath.Base(snap.OriginalPath), restoredHash[:12]))
		} else {
			// File was created by command, remove it
			if _, err := os.Stat(snap.OriginalPath); err == nil {
				_ = os.Remove(snap.OriginalPath)
				res.RemovedFiles = append(res.RemovedFiles, snap.OriginalPath)
			}
		}
	}

	return res, nil
}
