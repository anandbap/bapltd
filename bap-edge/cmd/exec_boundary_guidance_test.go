package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"bap-edge/internal/authz"
)

func TestDeniedEchoWriteNamesTheOutsideTarget(t *testing.T) {
	base := t.TempDir()
	// Go 1.24 may preserve an 8.3 TEMP spelling (e.g. RUNNER~1), while
	// boundary resolution correctly expands the existing ancestor to its real path.
	canonicalBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(base, "workspace")
	folder := filepath.Join(base, "sibling folder")
	target := filepath.Join(folder, "test_probe.txt")
	wantFolder := filepath.Join(canonicalBase, "sibling folder")
	wantTarget := filepath.Join(wantFolder, "test_probe.txt")
	for _, op := range []string{">", ">>"} {
		args := `test ` + op + ` "` + target + `"`
		got := deniedCommandTarget("echo", "echo "+args, args, workspace)
		if got != wantTarget {
			t.Fatalf("%s: target=%q, want %q", op, got, wantTarget)
		}
		suggestion := authz.FormatOutOfWorkspaceSuggestion(got, "fs:file:write", workspace)
		for _, want := range []string{wantFolder, "needs write access", "DEVELOPER ACTION REQUIRED"} {
			if !strings.Contains(suggestion, want) {
				t.Fatalf("suggestion missing %q: %s", want, suggestion)
			}
		}
	}
}
