package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestEarlierEnrollmentCannotBlockLiveSessionUploads(t *testing.T) {
	for _, key := range []string{"BAP_TEST_MODE", "LTD_TEST", "BAP_ENV", "BAP_RETAIN_LOCAL"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, id := range []string{"old-owner", "live-owner"} {
		e := AuditEntry{EventID: id, SessionID: id, Timestamp: time.Now().UTC(), Decision: "observed"}
		if err := Log(&e, path); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []AuditEntry
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		for _, entry := range batch {
			if entry.SessionID == "old-owner" {
				w.WriteHeader(403)
				return
			}
		}
		_, _ = w.Write([]byte(`{"durable":true,"chain_valid":true,"status":"acknowledged"}`))
	}))
	defer server.Close()
	n, err := FlushOfflineAudit(server.URL, path)
	if n != 1 || err == nil {
		t.Fatalf("live session blocked or refusal hidden: n=%d err=%v", n, err)
	}
	remaining, err := ReadEntries(path)
	if err != nil || len(remaining) != 1 || remaining[0].SessionID != "old-owner" {
		t.Fatalf("wrong retained evidence: %+v %v", remaining, err)
	}
}
