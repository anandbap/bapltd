package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
)

func TestAuditRetryDoesNotInflateSessionCounts(t *testing.T) {
	s := setupTestServer()
	stamp := time.Now().UTC().Add(-time.Second)
	payload, _ := json.Marshal([]audit.Event{{EventID: "delivery-retry", SessionID: "claude", Timestamp: stamp.Format(time.RFC3339Nano), Decision: "deny"}})
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/audit/ingest", bytes.NewReader(payload)))
		if w.Code != 200 {
			t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
		}
		var ack struct {
			Ingested   int    `json:"ingested"`
			Processing int64  `json:"processing_ms"`
			Age        int64  `json:"max_event_age_ms"`
			Received   string `json:"received_at"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
			t.Fatal(err)
		}
		if ack.Ingested != 1-i {
			t.Fatalf("retry ingested again: %+v", ack)
		}
		if _, err := time.Parse(time.RFC3339Nano, ack.Received); err != nil {
			t.Fatal(err)
		}
		if i == 0 && ack.Age < 1000 {
			t.Fatalf("missing age diagnostic: %+v", ack)
		}
	}
	sess, _ := s.sessionStore.Get("claude")
	if sess.TotalEvents != 1 || sess.DeniedCount != 1 {
		t.Fatalf("duplicate inflated counts: %+v", sess)
	}
	events := s.auditStore.List(0)
	if events[0].Timestamp != stamp.Format(time.RFC3339Nano) {
		t.Fatal("subsecond event order lost")
	}
}
