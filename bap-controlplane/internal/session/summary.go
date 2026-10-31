package session

import (
	"fmt"
	"time"
)

// GetSummary is used for ownership/liveness checks; audit history is not copied
// on each heartbeat or incoming event.
func (s *Store) GetSummary(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	cp := *sess
	cp.Events = nil
	if cp.Status == "active" && time.Since(cp.LastActiveAt) > 45*time.Second {
		cp.Status = "offline"
	}
	return &cp, nil
}
