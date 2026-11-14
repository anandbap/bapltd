package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorDetectsStaleHookCopy(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "user.exe"), filepath.Join(root, "project.exe")
	if err := os.WriteFile(a, []byte("matching-release"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("stale-release"), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := inspectHookCopies([]string{a, b, filepath.Join(root, "missing.exe")}, "")
	if err != nil || len(rows) != 3 || rows[0].Status != "MATCH" || rows[1].Status != "MISMATCH" || rows[2].Status != "MISSING" {
		t.Fatalf("unexpected copies: %+v %v", rows, err)
	}
	rows, err = inspectHookCopies([]string{b}, rows[0].SHA256)
	if err != nil || rows[0].Status != "MISMATCH" {
		t.Fatal("approved manifest hash was not checked")
	}
}
