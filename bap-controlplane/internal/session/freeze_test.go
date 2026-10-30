package session

import (
	"testing"
	"time"
)

func TestFreezeStaleSessionAndUnfreeze(t *testing.T) {
	s := NewStore()
	if _, err := s.Start(SessionStartRequest{SessionID: "stale", AppID: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.sessions["stale"].LastActiveAt = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	before, _ := s.Get("stale")
	if before.Status != "offline" {
		t.Fatalf("expected stale session, got %s", before.Status)
	}
	for _, frozen := range []bool{true, true, false} {
		got, err := s.SetFrozen("stale", frozen)
		if err != nil {
			t.Fatal(err)
		}
		if (got.Status == "revoked") != frozen {
			t.Fatalf("wrong freeze state: %+v", got)
		}
	}
}

func TestSessionFreezeDoesNotCascadeOrClearOtherRevocations(t *testing.T) {
	s := NewStore()
	_, _ = s.Start(SessionStartRequest{SessionID: "parent", AppID: "claude-code"})
	_, _ = s.Start(SessionStartRequest{SessionID: "child", AppID: "claude-code", ParentSessionID: "parent"})
	if _, err := s.SetFrozen("parent", true); err != nil {
		t.Fatal(err)
	}
	if s.IsRevoked("child") {
		t.Fatal("session freeze cascaded to another session")
	}
	_, _ = s.SetFrozen("parent", false)
	_ = s.RevokeSession("parent", "Access revoked")
	if _, err := s.SetFrozen("parent", false); err == nil {
		t.Fatal("unfreeze cleared a security revocation")
	}
}
