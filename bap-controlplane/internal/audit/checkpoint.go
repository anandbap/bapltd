package audit

import "fmt"

// CheckpointSuffix returns immutable canonical links not yet durably committed.
func (s *Store) CheckpointSuffix(after int) ([]Event, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if after < 0 || after > len(s.events) {
		return nil, 0, fmt.Errorf("audit checkpoint frontier moved backwards")
	}
	return append([]Event(nil), s.events[after:]...), len(s.events), nil
}

func (s *Store) RestoreCheckpoint(events []Event) error {
	loaded := NewStore()
	for _, ev := range events {
		if ev.EventID == "" {
			return fmt.Errorf("audit checkpoint contains an unidentified event")
		}
		if _, ok := loaded.seenIDs[ev.EventID]; ok {
			return fmt.Errorf("audit checkpoint contains duplicate event IDs")
		}
		loaded.seenIDs[ev.EventID] = struct{}{}
		loaded.events = append(loaded.events, ev)
		loaded.lastHash = ev.EventHash
	}
	if valid, err := loaded.VerifyChain(); !valid {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events, s.seenIDs, s.lastHash = loaded.events, loaded.seenIDs, loaded.lastHash
	s.verifiedCount, s.verifiedHash, s.integrityFailure = 0, "", nil
	return nil
}
