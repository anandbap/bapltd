package state

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExplicitStatePurgeCannotReachAnotherInstallation(t *testing.T) {
	root := t.TempDir()
	t.Setenv("BAP_STATE_DIR", root)
	t.Setenv("BAP_CREDENTIALS", "")
	ResetForTesting()
	t.Cleanup(ResetForTesting)
	for _, path := range credentialPurgePaths("") {
		if path == "" {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("isolated logout would erase another installation: %s", path)
		}
	}
}
