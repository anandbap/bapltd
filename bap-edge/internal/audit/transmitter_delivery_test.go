package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConcurrentFlushPreservesNewEventsAndUploadsBacklogOnce(t *testing.T) {
	for _, key := range []string{"BAP_TEST_MODE", "LTD_TEST", "BAP_ENV", "BAP_RETAIN_LOCAL"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	appendEvent := func(id string) {
		t.Helper()
		e := AuditEntry{EventID: id, SessionID: "delivery-session", FullCommand: id, Decision: "allow", Timestamp: time.Now().UTC()}
		if err := Log(&e, path); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		appendEvent(fmt.Sprintf("action-%d", i))
	}
	started, release := make(chan struct{}), make(chan struct{})
	concurrentRequest := make(chan struct{}, 1)
	var mu sync.Mutex
	seen := map[string]int{}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []AuditEntry
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		requests++
		first := requests == 1
		for _, e := range batch {
			seen[e.EventID]++
		}
		mu.Unlock()
		if first {
			close(started)
			<-release
		} else {
			select {
			case concurrentRequest <- struct{}{}:
			default:
			}
		}
		_, _ = w.Write([]byte(`{"durable":true,"chain_valid":true,"status":"acknowledged"}`))
	}))
	defer server.Close()
	type result struct {
		n   int
		err error
	}
	results := make(chan result, 2)
	flush := func() { n, err := FlushOfflineAudit(server.URL, path); results <- result{n, err} }
	go flush()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("first upload did not start")
	}
	// Logging must remain available while a slow upload is in flight. Removing
	// that upload's snapshot must not discard evidence appended in the meantime.
	appendEvent("during-upload")
	go flush()
	select {
	case <-concurrentRequest:
		close(release)
		t.Fatal("second flush uploaded the in-flight snapshot")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	total := 0
	for i := 0; i < 2; i++ {
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatal(got.err)
			}
			total += got.n
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent flush did not finish")
		}
	}
	if total != 21 {
		t.Fatalf("flushed %d events, want 21", total)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 21 {
		t.Fatalf("delivered %d distinct events, want 21", len(seen))
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("event %s uploaded %d times", id, count)
		}
	}
	entries, err := ReadEntries(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("remaining spool: %v, %v", entries, err)
	}
}

func TestRejectedAuditRemainsQueuedUntilVerifiedAcknowledgement(t *testing.T) {
	t.Setenv("BAP_RETAIN_LOCAL", "0")
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	entry := AuditEntry{EventID: "delivery", Source: "claude-code", FullCommand: "git status", Decision: "deny", Timestamp: time.Now().UTC()}
	if err := Log(&entry, logPath); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	status, ack := http.StatusForbidden, `{"chain_valid":true,"status":"acknowledged","ingested":1}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		curStatus, curAck := status, ack
		mu.Unlock()
		w.WriteHeader(curStatus)
		_, _ = w.Write([]byte(curAck))
	}))
	defer server.Close()
	for _, failure := range []struct {
		code int
		body string
	}{
		{http.StatusForbidden, ack},
		{http.StatusOK, `{"chain_valid":false,"status":"acknowledged","ingested":1}`},
	} {
		mu.Lock()
		status, ack = failure.code, failure.body
		mu.Unlock()
		if n, err := FlushOfflineAudit(server.URL, logPath); err == nil || n != 0 {
			t.Fatalf("rejection reported success: %d %v", n, err)
		}
		entries, err := ReadEntries(logPath)
		if err != nil || len(entries) != 1 {
			t.Fatalf("lost unacknowledged event: %v %v", entries, err)
		}
	}
	mu.Lock()
	status, ack = http.StatusOK, `{"chain_valid":true,"status":"acknowledged","ingested":0}`
	mu.Unlock()
	if n, err := FlushOfflineAudit(server.URL, logPath); err != nil || n != 1 {
		t.Fatalf("retry: %d %v", n, err)
	}
	entries, err := ReadEntries(logPath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("acknowledged event still queued: %v %v", entries, err)
	}
}

func TestTransmitDuplicateAckPreservesTimestampPrecision(t *testing.T) {
	for _, key := range []string{"BAP_TEST_MODE", "LTD_TEST", "BAP_ENV", "BAP_RETAIN_LOCAL"} {
		t.Setenv(key, "")
	}
	stamp := time.Date(2026, 10, 30, 12, 0, 0, 123456789, time.UTC)
	entry := AuditEntry{EventID: "precision", Source: "claude-code", FullCommand: "git status", Decision: "allow", Timestamp: stamp}
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := Log(&entry, logPath); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []struct {
			Timestamp string `json:"timestamp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		if len(batch) != 1 || batch[0].Timestamp != stamp.Format(time.RFC3339Nano) {
			t.Errorf("timestamp precision lost: %+v", batch)
		}
		_, _ = w.Write([]byte(`{"chain_valid":true,"status":"acknowledged","ingested":0}`))
	}))
	defer server.Close()
	if ok, _, err := Transmit(entry, server.URL, logPath); !ok || err != nil {
		t.Fatalf("duplicate acknowledgement: %v %v", ok, err)
	}
	entries, _ := ReadEntries(logPath)
	if len(entries) != 0 {
		t.Fatal("duplicate kept retrying forever")
	}
}
