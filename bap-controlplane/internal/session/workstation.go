package session

import "strings"

// ClearWorkstationLogout removes synthetic placeholders created by logout
// handling for this workstation or agent. Real execution sessions and administrator
// revocations remain revoked. Call only after a newly verified workstation enrollment.
func (s *Store) ClearWorkstationLogout(agentID, instanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	toDelete := make([]string, 0)
	for id, sess := range s.sessions {
		if id == "" || sess == nil || sess.AppID != "unknown" || sess.ClientPID != 0 ||
			sess.Status != "revoked" || sess.CloseReason != "Deregistered via logout" {
			continue
		}
		match := id == agentID || id == instanceID
		if !match && instanceID != "" && strings.Contains(id, instanceID) {
			match = true
		}
		if match {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		if s.db != nil {
			if _, err := s.db.Exec("DELETE FROM sessions WHERE session_id = ?", id); err != nil {
				return err
			}
		}
		delete(s.sessions, id)
		for i, existing := range s.order {
			if existing == id {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
	}
	return nil
}
