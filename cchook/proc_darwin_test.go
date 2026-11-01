//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinProcessExecutablePath(t *testing.T) {
	path := getProcessExecutablePath(os.Getpid())
	if !filepath.IsAbs(path) {
		t.Fatalf("expected absolute executable path, got %q", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("executable path is unavailable: %v", err)
	}
}

func TestDarwinInvalidProcessIDs(t *testing.T) {
	for _, pid := range []int{-1, 0} {
		if parent := getParentPID(pid); parent != 0 {
			t.Errorf("getParentPID(%d) = %d", pid, parent)
		}
		if path := getProcessExecutablePath(pid); path != "" {
			t.Errorf("getProcessExecutablePath(%d) = %q", pid, path)
		}
	}
}
