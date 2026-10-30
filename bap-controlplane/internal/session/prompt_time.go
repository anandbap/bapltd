package session

import "time"

// LatestPromptTime returns the observation time of the current session prompt.
func (s *Store) LatestPromptTime(sessionID string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest time.Time
	for _, prompt := range s.prompts {
		if prompt.SessionID == sessionID && prompt.Timestamp.After(latest) {
			latest = prompt.Timestamp
		}
	}
	return latest
}
