package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/session"
)

func TestRiskyAuditPaginationIncludesOlderActionsAndStableSnapshot(t *testing.T) {
	s := setupTestServer()
	for i := 0; i < 260; i++ {
		d := "deny"
		if i%2 == 0 {
			d = "audit_permitted"
		}
		s.auditStore.Ingest([]audit.Event{{SessionID: "same-session", Decision: d, FullCommand: fmt.Sprintf("action-%d", i), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}})
	}
	// Recent allowed operations must not hide older risky operations.
	for i := 0; i < 150; i++ {
		s.auditStore.Ingest([]audit.Event{{Decision: "allow", FullCommand: fmt.Sprintf("allowed-%d", i)}})
	}
	seen := map[string]bool{}
	url := "/api/v1/audit/risky-events?limit=100"
	for page := 0; ; page++ {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 200 {
			t.Fatalf("%d: %s", w.Code, w.Body.String())
		}
		var result struct {
			Events   []audit.Event `json:"events"`
			Total    int           `json:"total"`
			Snapshot int           `json:"snapshot"`
			Next     int           `json:"next_offset"`
			More     bool          `json:"has_more"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Total != 260 {
			t.Fatalf("missing risks: %d", result.Total)
		}
		for _, ev := range result.Events {
			if seen[ev.EventHash] {
				t.Fatal("duplicate event across pages")
			}
			seen[ev.EventHash] = true
		}
		if !result.More {
			break
		}
		if page == 0 {
			s.auditStore.Ingest([]audit.Event{{Decision: "deny", FullCommand: "new-risk"}})
		}
		url = fmt.Sprintf("/api/v1/audit/risky-events?limit=100&offset=%d&snapshot=%d", result.Next, result.Snapshot)
	}
	if len(seen) != 260 {
		t.Fatalf("got %d risks", len(seen))
	}
}

func TestFreezeIdleClaudeSessionReturnsToggleState(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "idle-claude", AppID: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.sessionStore.End("idle-claude", "idle_timeout"); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"freeze", "unfreeze"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/control/agent/kill", strings.NewReader(`{"target":"idle-claude","scope":"session","action":"`+action+`"}`))
		r.Header.Set("X-BAP-Admin-Token", "test-admin")
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
		}
		var result struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		want := "active"
		if action == "freeze" {
			want = "revoked"
		}
		if result.Status != want {
			t.Fatalf("%s returned %s", action, result.Status)
		}
	}
}
