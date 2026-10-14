package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotAndRollbackCycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bap-snap-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "config.txt")
	originalContent := "initial-state-token-12345\nfeature_flag=false"
	if err := os.WriteFile(testFile, []byte(originalContent), 0644); err != nil {
		t.Fatalf("failed writing test file: %v", err)
	}

	sessionID := "sess-unit-snap-01"

	// 1. Create checkpoint before mutating command
	manifest, err := CreateCheckpoint(sessionID, "echo mutated > config.txt", []string{testFile})
	if err != nil {
		t.Fatalf("failed creating checkpoint: %v", err)
	}
	if manifest == nil {
		t.Fatal("expected non-nil manifest")
	}
	if len(manifest.Files) != 1 {
		t.Fatalf("expected 1 snapshotted file, got %d", len(manifest.Files))
	}

	// 2. Perform mutating file operation
	mutatedContent := "malicious-injection-token-99999\nfeature_flag=true"
	if err := os.WriteFile(testFile, []byte(mutatedContent), 0644); err != nil {
		t.Fatalf("failed writing mutated file: %v", err)
	}

	// Verify file is mutated
	cur, _ := os.ReadFile(testFile)
	if string(cur) != mutatedContent {
		t.Fatalf("file was not mutated")
	}

	// 3. Rollback to checkpoint
	res, err := Rollback(sessionID, manifest.CheckpointID, testFile)
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if len(res.RestoredFiles) != 1 {
		t.Fatalf("expected 1 restored file, got %d", len(res.RestoredFiles))
	}

	// 4. Verify file was restored to initial state
	restored, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed reading restored file: %v", err)
	}
	if string(restored) != originalContent {
		t.Fatalf("restoration failed: expected %q, got %q", originalContent, string(restored))
	}
}

func TestRollbackRemovesNewlyCreatedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bap-snap-newfile-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	newFile := filepath.Join(tmpDir, "unwanted-created.txt")
	sessionID := "sess-unit-snap-02"

	// Checkpoint target that does not exist yet
	manifest, err := CreateCheckpoint(sessionID, "echo unwanted > unwanted-created.txt", []string{newFile})
	if err != nil {
		t.Fatalf("failed creating checkpoint: %v", err)
	}
	if manifest == nil {
		t.Fatal("expected manifest")
	}

	// Now create file
	_ = os.WriteFile(newFile, []byte("unwanted content"), 0644)
	if _, err := os.Stat(newFile); os.IsNotExist(err) {
		t.Fatal("new file should exist")
	}

	// Rollback: should remove the file
	res, err := Rollback(sessionID, manifest.CheckpointID, newFile)
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if len(res.RemovedFiles) != 1 {
		t.Fatalf("expected 1 removed file, got %d", len(res.RemovedFiles))
	}

	// Verify file was deleted
	if _, err := os.Stat(newFile); !os.IsNotExist(err) {
		t.Fatalf("file should have been removed by rollback")
	}
}
