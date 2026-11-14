package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// Shared markers (pid-<PID>.json, session.json) name the newest session on an agent process. An older
// session ending must leave a marker that now names a newer session alone, or discovery can no longer
// adopt the new native session and reports a duplicate observed one.
func TestRemoveOwnedMarker(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body, ending string
		wantRemoved        bool
	}{
		{"owned", `{"session_id":"a"}`, "a", true},
		{"other session", `{"session_id":"b"}`, "a", false},
		{"other session, ending id unknown", `{"session_id":"b"}`, "", false},
		{"no session id", `{}`, "a", true},
		{"corrupt", `not json`, "a", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			removeOwnedMarker(p, tc.ending)
			_, err := os.Stat(p)
			if removed := os.IsNotExist(err); removed != tc.wantRemoved {
				t.Fatalf("removed=%v, want %v", removed, tc.wantRemoved)
			}
		})
	}
	removeOwnedMarker(filepath.Join(dir, "missing.json"), "a") // must not panic
}
