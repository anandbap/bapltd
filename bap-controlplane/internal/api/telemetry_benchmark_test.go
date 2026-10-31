package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/session"
)

// Exercises the real ingestion handler with retained history and durable SQLite
// session updates. This is a local service benchmark, not a network/Render SLA.
func BenchmarkTelemetryIngest(b *testing.B) {
	for _, history := range []int{1000, 10000} {
		for _, batch := range []int{1, 50} {
			b.Run(fmt.Sprintf("history%d/batch%d", history, batch), func(b *testing.B) {
				s := setupTestServer()
				proof := recoveryProof(b, s, "benchmark-machine")
				store, err := session.NewStoreWithDB(filepath.Join(b.TempDir(), "sessions.db"))
				if err != nil {
					b.Fatal(err)
				}
				defer store.Close()
				s.sessionStore = store
				seed := make([]audit.Event, history)
				for i := range seed {
					seed[i] = audit.Event{EventID: fmt.Sprintf("seed-%d", i), Decision: "allow"}
				}
				_, _ = s.auditStore.Ingest(seed)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					events := make([]audit.Event, batch)
					for j := range events {
						events[j] = audit.Event{EventID: fmt.Sprintf("delivery-%d-%d", i, j), SessionID: fmt.Sprintf("session-%d", (i*batch+j)%100), Source: "claude-code", Decision: "allow", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
					}
					body, _ := json.Marshal(events)
					w := httptest.NewRecorder()
					r := httptest.NewRequest("POST", "/api/v1/audit/ingest", bytes.NewReader(body))
					r.Header.Set("Authorization", "Bearer "+proof)
					s.Handler().ServeHTTP(w, r)
					if w.Code != 200 {
						b.Fatalf("ingest %d: %s", w.Code, w.Body.String())
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(b.N*batch)/b.Elapsed().Seconds(), "events/s")
			})
		}
	}
}
