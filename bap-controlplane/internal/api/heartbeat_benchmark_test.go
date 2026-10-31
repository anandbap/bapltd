package api

import (
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"bap-controlplane/internal/session"
)

func BenchmarkAuthenticatedHeartbeat(b *testing.B) {
	for _, fleet := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("fleet%d", fleet), func(b *testing.B) {
			s := setupTestServer()
			store, err := session.NewStoreWithDB(filepath.Join(b.TempDir(), "sessions.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer store.Close()
			s.sessionStore = store
			for i := 0; i < fleet; i++ {
				s.registry.EnsureSessionAgent("bapedge", fmt.Sprintf("machine-%d", i), "", "", "")
			}
			_, _ = store.Start(session.SessionStartRequest{SessionID: "live", AppID: "claude-code", InstanceID: "machine-0"})
			proof := recoveryProof(b, s, "machine-0")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := httptest.NewRequest("POST", "/api/v1/sessions/heartbeat", strings.NewReader(`{"session_id":"live"}`))
				r.Header.Set("Authorization", "Bearer "+proof)
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != 200 {
					b.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
}
