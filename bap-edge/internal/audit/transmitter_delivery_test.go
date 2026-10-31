package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRejectedAuditRemainsQueuedUntilVerifiedAcknowledgement(t *testing.T) {
	t.Setenv("BAP_RETAIN_LOCAL", "0")
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	entry := AuditEntry{EventID: "delivery", Source: "claude-code", FullCommand: "git status", Decision: "deny", Timestamp: time.Now().UTC()}
	if err := Log(&entry, logPath); err != nil {
		t.Fatal(err)
	}
	status, ack := http.StatusForbidden, `{"chain_valid":true,"status":"acknowledged","ingested":1}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(ack))
	}))
	defer server.Close()
	for _, failure := range []struct {
		code int
		body string
	}{
		{http.StatusForbidden, ack},
		{http.StatusOK, `{"chain_valid":false,"status":"acknowledged","ingested":1}`},
	} {
		status, ack = failure.code, failure.body
		if n, err := FlushOfflineAudit(server.URL, logPath); err == nil || n != 0 {
			t.Fatalf("rejection reported success: %d %v", n, err)
		}
		entries, err := ReadEntries(logPath)
		if err != nil || len(entries) != 1 {
			t.Fatalf("lost unacknowledged event: %v %v", entries, err)
		}
	}
	status, ack = http.StatusOK, `{"chain_valid":true,"status":"acknowledged","ingested":0}`
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
