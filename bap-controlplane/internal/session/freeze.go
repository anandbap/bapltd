package session

import (
	"fmt"
	"time"
)

const FrozenReason = "Frozen by administrator"

// SetFrozen changes only this session. A stale heartbeat does not remove the
// administrator's ability to block its next execution.
func (s *Store) SetFrozen(id string, frozen bool) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	if frozen {
		if sess.Status != "active" && sess.Status != "offline" && !(sess.Status == "closed" && sess.CloseReason == "idle_timeout") && !(sess.Status == "revoked" && sess.CloseReason == FrozenReason) {
			return nil, fmt.Errorf("session is ended or revoked; cannot freeze")
		}
		sess.Status, sess.CloseReason = "revoked", FrozenReason
	} else {
		if sess.Status != "revoked" || sess.CloseReason != FrozenReason {
			return nil, fmt.Errorf("session is not frozen; cannot clear another revocation")
		}
		sess.Status, sess.CloseReason = "active", ""
		sess.EndedAt = nil
	}
	sess.LastActiveAt = time.Now().UTC()
	s.saveSessionToDB(sess)
	cp := *sess
	cp.Events = nil
	return &cp, nil
}
