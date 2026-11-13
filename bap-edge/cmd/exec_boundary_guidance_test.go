package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"bap-edge/internal/authz"
)

func TestDeniedEchoWriteNamesTheOutsideTarget(t *testing.T) {
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	folder := filepath.Join(base, "sibling folder")
	target := filepath.Join(folder, "test_probe.txt")
	for _, op := range []string{">", ">>"} {
		args := `test ` + op + ` "` + target + `"`
		got := deniedCommandTarget("echo", "echo "+args, args, workspace)
		if got != target {
			t.Fatalf("%s: target=%q, want %q", op, got, target)
		}
		suggestion := authz.FormatOutOfWorkspaceSuggestion(got, "fs:file:write", workspace)
		for _, want := range []string{folder, "needs write access", "DEVELOPER ACTION REQUIRED"} {
			if !strings.Contains(suggestion, want) {
				t.Fatalf("suggestion missing %q: %s", want, suggestion)
			}
		}
	}
}
