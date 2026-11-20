package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
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

func TestFlushPromptSpoolPreservesRefusedOldAndMalformedEvidence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	mine := writeSpool(t, "old-mine.json", "sess-a")
	other := writeSpool(t, "old-other.json", "sess-b")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(other, old, old); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(promptSpoolDir(), "malformed.json")
	if err := os.WriteFile(malformed, []byte("partial unacknowledged evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	flushPromptSpool(srv.URL, "sess-a")
	for _, path := range []string{mine, other, malformed} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("unacknowledged evidence deleted", path, err)
		}
	}
}

func TestLifecycleOutboxRetriesAfterSessionExitAndCleansDeliveredFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var online atomic.Bool
	var delivered atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !online.Load() {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path != "/api/v1/sessions/end" {
			t.Error("wrong lifecycle replay endpoint", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["session_id"] != "ended-while-offline" || body["event_id"] != "stable-end-event" {
			t.Error("replay changed identity", body)
		}
		delivered.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	payload := map[string]any{"session_id": "ended-while-offline", "event_id": "stable-end-event", "reason": "process exited"}
	if err := postJSONQuick(srv.URL+"/api/v1/sessions/end", payload); err == nil {
		t.Fatal("outage reported as delivered")
	}
	entries, err := os.ReadDir(promptSpoolDir())
	if err != nil || len(entries) != 1 {
		t.Fatal("durable pending envelope missing", entries, err)
	}
	online.Store(true)
	flushPromptSpool(srv.URL, "") // daemon replay, without any live-session marker
	entries, err = os.ReadDir(promptSpoolDir())
	if err != nil || len(entries) != 0 {
		t.Fatal("delivered envelope left behind", entries, err)
	}
	flushPromptSpool(srv.URL, "")
	if delivered.Load() != 1 {
		t.Fatal("delivered envelope resent", delivered.Load())
	}
}

func TestFlushPromptSpoolReplaysAndRemoves(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mine := writeSpool(t, "00000000000000000001-1.json", "sess-a")
	other := writeSpool(t, "00000000000000000002-1.json", "sess-b")

	flushPromptSpool(srv.URL, "sess-a")

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected exactly one replay, got %d", got)
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
