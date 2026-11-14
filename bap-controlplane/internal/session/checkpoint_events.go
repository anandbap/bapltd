package session

import "bap-controlplane/internal/audit"

// RestoreEventDetails rebuilds drill-down evidence without incrementing persisted counters.
func (s *Store) RestoreEventDetails(events []audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		sess.Events = nil
	}
	for _, event := range events {
		if sess := s.sessions[event.SessionID]; sess != nil {
			sess.Events = append(sess.Events, event)
		}
	}
}
