package session

import (
	"testing"
	"time"

	"bap-controlplane/internal/audit"
)

// An old (closed) and a new (active) session share one agent PID. A discovered "observed" process for
// that PID must reconcile to the new live session every time, not to whichever the map yields first.
func TestObservedProcessReconcilesToLiveSessionNotClosedOne(t *testing.T) {
	for i := 0; i < 50; i++ { // map iteration order is random; repeat to catch nondeterminism
		s := NewStore()
		for _, id := range []string{"old-sess", "new-sess"} {
			if _, err := s.Start(SessionStartRequest{SessionID: id, AppID: "claude-code", InstanceID: "ws-1", ClientPID: 4242}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.End("old-sess", "idle_timeout"); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.sessions["old-sess"].LastActiveAt = time.Now().UTC().Add(-10 * time.Minute)
		s.mu.Unlock()

		ev := audit.Event{SessionID: "observed-claude-code-abc", InstanceID: "ws-1", ClientPID: 4242, Source: "claude-code"}
		if err := s.ReserveReportingSessions([]audit.Event{ev}, func(string) string { return "" }); err != nil {
			t.Fatal(err)
		}
		s.mu.RLock()
		obs := s.sessions["observed-claude-code-abc"]
		s.mu.RUnlock()
		if obs == nil || obs.ReconciledTo != "new-sess" {
			t.Fatalf("iteration %d: observed process reconciled to %+v, want new-sess", i, obs)
		}
	}
}

func TestManagedSessionForPID_NoMatchAndInstanceMismatch(t *testing.T) {
	s := NewStore()
	if _, err := s.Start(SessionStartRequest{SessionID: "a", AppID: "claude-code", InstanceID: "ws-1", ClientPID: 7}); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.managedSessionForPIDLocked(0, "ws-1") != nil {
		t.Fatal("pid 0 must never match")
	}
	if s.managedSessionForPIDLocked(8, "ws-1") != nil {
		t.Fatal("a different pid must not match")
	}
	if s.managedSessionForPIDLocked(7, "ws-2") != nil {
		t.Fatal("a different workstation instance must not match")
	}
	if got := s.managedSessionForPIDLocked(7, ""); got == nil || got.SessionID != "a" {
		t.Fatalf("empty instance should match on pid alone, got %+v", got)
	}
}
