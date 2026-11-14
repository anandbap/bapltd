package session

import (
	"testing"
	"time"
)

// Two Claude sessions on one workstation instance: when the older one ends, the newer one (quiet for
// longer than the 45s dashboard cutoff, as a prompt-driven session often is) must still count as live.
func TestHasActiveSessionsForInstance_QuietNewSessionKeepsInstanceAlive(t *testing.T) {
	s := NewStore()
	for _, id := range []string{"old-sess", "new-sess"} {
		if _, err := s.Start(SessionStartRequest{SessionID: id, AppID: "claude-code", InstanceID: "ws-1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.End("old-sess", "idle_timeout"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.sessions["new-sess"].LastActiveAt = time.Now().UTC().Add(-2 * time.Minute)
	s.mu.Unlock()

	if !s.HasActiveSessionsForInstance("ws-1") {
		t.Fatal("new session quiet for 2m must keep the shared instance alive after the old session ends")
	}
}

func TestHasActiveSessionsForInstance_DeadSessionDoesNotKeepInstanceAlive(t *testing.T) {
	s := NewStore()
	if _, err := s.Start(SessionStartRequest{SessionID: "dead-sess", AppID: "claude-code", InstanceID: "ws-2"}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.sessions["dead-sess"].LastActiveAt = time.Now().UTC().Add(-InstanceLivenessWindow - time.Minute)
	s.mu.Unlock()

	if s.HasActiveSessionsForInstance("ws-2") {
		t.Fatal("a session idle beyond the liveness window must not keep the instance alive")
	}
}
