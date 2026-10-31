package session

import (
	"testing"
	"time"

	"bap-controlplane/internal/audit"
)

func TestOfflineAuditReplayDoesNotReviveEndedSession(t *testing.T) {
	s := NewStore()
	_, _ = s.Start(SessionStartRequest{SessionID: "ended", AppID: "claude-code"})
	_ = s.End("ended", "Workload exited")
	before, _ := s.Get("ended")
	s.RecordEvent("ended", audit.Event{Decision: "deny", Timestamp: time.Now().Add(-time.Hour).Format(time.RFC3339Nano)})
	after, _ := s.Get("ended")
	if after.Status != "closed" || !after.LastActiveAt.Equal(before.LastActiveAt) {
		t.Fatal("delayed audit changed presence")
	}
	s.RecordEvent("historical", audit.Event{Decision: "allow", Timestamp: time.Now().Add(-time.Hour).Format(time.RFC3339Nano)})
	historical, _ := s.Get("historical")
	if historical.Status != "offline" {
		t.Fatal("old replay presented as live")
	}
}
