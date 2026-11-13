package capability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialReadOnlyMountsRemainImmutable(t *testing.T) {
	ws := t.TempDir()
	for _, path := range []string{filepath.Join(ws, ".ssh"), filepath.Join(ws, ".env"), filepath.Join(ws, ".env", "nested"), filepath.Join(ws, ".aws", "config")} {
		profile := New(ws)
		profile.ReadOnly = []string{path}
		if err := profile.Validate(); err == nil {
			t.Errorf("credential mount accepted: %s", path)
		}
	}
	secretDir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "innocent-cache")
	if err := os.Symlink(secretDir, alias); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	profile := New(ws)
	profile.ReadOnly = []string{alias}
	if err := profile.Validate(); err == nil {
		t.Fatal("symlink alias exposed a credential directory")
	}
}
