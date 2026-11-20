package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOutageReconnectRetainsIdentityDrainsPendingAndCleansStaging(t *testing.T) {
	for _, key := range []string{"BAP_TEST_MODE", "LTD_TEST", "BAP_ENV", "BAP_RETAIN_LOCAL"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	entry := AuditEntry{EventID: "offline-stable-id", SessionID: "offline-session", ReportingLayer: "broker", Source: "claude-code", Decision: "allow", Timestamp: time.Now().UTC()}
	if err := Log(&entry, path); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	online := false
	deliveries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !online {
			w.WriteHeader(503)
			return
		}
		var events []AuditEntry
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if len(events) != 1 || events[0].EventID != entry.EventID || events[0].SessionID != entry.SessionID || events[0].ReportingLayer != "broker" {
			t.Errorf("retry changed attribution: %+v", events)
		}
		deliveries++
		_, _ = w.Write([]byte(`{"durable":true,"chain_valid":true,"status":"acknowledged","ingested":1}`))
	}))
	defer server.Close()
	if n, err := FlushOfflineAudit(server.URL, path); err == nil || n != 0 {
		t.Fatal("outage falsely acknowledged", n, err)
	}
	remaining, err := ReadEntries(path)
	if err != nil || len(remaining) != 1 {
		t.Fatal("offline evidence lost", remaining, err)
	}
	mu.Lock()
	online = true
	mu.Unlock()
	if n, err := FlushOfflineAudit(server.URL, path); err != nil || n != 1 {
		t.Fatal("reconnect did not drain", n, err)
	}
	if n, err := FlushOfflineAudit(server.URL, path); err != nil || n != 0 {
		t.Fatal("drained event retried", n, err)
	}
	mu.Lock()
	count := deliveries
	mu.Unlock()
	if count != 1 {
		t.Fatal("duplicate delivery after drain", count)
	}
	if remaining, err := ReadEntries(path); err != nil || len(remaining) != 0 {
		t.Fatal("pending spool not empty", remaining, err)
	}
	stages, err := filepath.Glob(path + ".pending-*")
	if err != nil || len(stages) != 0 {
		t.Fatal("disposable staging files left", stages, err)
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatal("stale transient lock left", err)
	}
}

func TestAtomicPruneRetainsMalformedAndUnacknowledgedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, id := range []string{"acked", "pending"} {
		if err := Log(AuditEntry{EventID: id, Decision: "allow"}, path); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("retained malformed evidence\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if err := RemoveEntry("acked", path); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadEntries(path)
	if err != nil || len(entries) != 1 || entries[0].EventID != "pending" {
		t.Fatal(entries, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("retained malformed evidence")) {
		t.Fatal("unknown evidence removed during cleanup")
	}
}
