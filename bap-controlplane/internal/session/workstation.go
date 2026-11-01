package session

// ClearWorkstationLogout removes only synthetic placeholders made by older
// logout handling. Real execution sessions and administrator revocations remain
// revoked. Call only after a newly verified workstation enrollment.
func (s *Store) ClearWorkstationLogout(agentID, instanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range []string{agentID, instanceID} {
		sess := s.sessions[id]
		if id == "" || sess == nil || sess.AppID != "unknown" || sess.InstanceID != "" ||
			sess.ClientPID != 0 || sess.Status != "revoked" || sess.CloseReason != "Deregistered via logout" {
			continue
		}
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
