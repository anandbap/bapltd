package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeSpool(t *testing.T, name, session string) string {
	t.Helper()
	dir := promptSpoolDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(`{"session_id":"`+session+`","body":{"session_id":"`+session+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFlushPromptSpoolReplaysAndRemoves(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mine := writeSpool(t, "00000000000000000001-1.json", "sess-a")
	other := writeSpool(t, "00000000000000000002-1.json", "sess-b")

	flushPromptSpool(srv.URL, "sess-a")

	if hits != 1 {
		t.Fatalf("expected exactly one replay, got %d", hits)
	}
	if _, err := os.Stat(mine); !os.IsNotExist(err) {
		t.Fatal("delivered spool entry should be removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("other session's entry must be left for its own watcher")
	}
}

func TestFlushPromptSpoolKeepsEntryOnServerError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // session not enrolled yet
	}))
	defer srv.Close()

	p := writeSpool(t, "00000000000000000001-1.json", "sess-a")
	flushPromptSpool(srv.URL, "sess-a")
	if _, err := os.Stat(p); err != nil {
		t.Fatal("entry must be retained while the session is not enrolled (404)")
	}
}
