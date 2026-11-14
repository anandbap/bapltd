package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: two Claude sessions share one agent process, so they share pid-<PID>.json and
// session.json, and the newest session owns them. The OLD session's SessionEnd must not delete them.
func TestSessionEnd_OldSessionDoesNotWipeNewSessionMarkers(t *testing.T) {
	state := t.TempDir()
	ws := t.TempDir()
	t.Setenv("BAP_STATE_DIR", state)
	t.Setenv("BAP_WORKSPACE_ROOT", ws)
	wd, _ := os.Getwd()
	if err := os.Chdir(ws); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	const pid = 4242
	write := func(path, sessionID string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"session_id":"`+sessionID+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pidMarker := sessionMarkerPathForPID(pid)
	shared := filepath.Join(state, "session.json")

	// The new session started last, so it owns the shared markers.
	write(pidMarker, "new-sess")
	write(shared, "new-sess")

	cleanupSessionMarkers("old-sess", pid)

	for _, p := range []string{pidMarker, shared} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("old session's end deleted the new session's marker %s: %v", p, err)
		}
	}

	// A session ending cleans up the markers it owns.
	cleanupSessionMarkers("new-sess", pid)
	for _, p := range []string{pidMarker, shared} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("session's own marker %s should be removed, stat err=%v", p, err)
		}
	}
}

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
