package session

import "strings"

// managedSessionForPIDLocked returns the managed (non-observed) session an observed process with
// this client PID should reconcile to. Multiple sessions can share one agent PID over time (an old
// session that ended or timed out, and the new one that replaced it), so the choice must be stable:
// a live session beats a closed one, then the most recently active, then the most recently started,
// then session id as a final deterministic tie-break. Caller must hold s.mu.
func (s *Store) managedSessionForPIDLocked(clientPID int, instanceID string) *Session {
	if clientPID <= 0 {
		return nil
	}
	var best *Session
	for _, m := range s.sessions {
		if strings.HasPrefix(m.SessionID, "observed-") || m.ClientPID != clientPID {
			continue
		}
		if m.Status != "active" && m.Status != "closed" {
			continue
		}
		if m.InstanceID != "" && instanceID != "" && m.InstanceID != instanceID {
			continue
		}
		if best == nil || preferManagedForPID(m, best) {
			best = m
		}
	}
	return best
}

// preferManagedForPID reports whether a should be chosen over b.
func preferManagedForPID(a, b *Session) bool {
	if (a.Status == "active") != (b.Status == "active") {
		return a.Status == "active"
	}
	if !a.LastActiveAt.Equal(b.LastActiveAt) {
		return a.LastActiveAt.After(b.LastActiveAt)
	}
	if !a.StartedAt.Equal(b.StartedAt) {
		return a.StartedAt.After(b.StartedAt)
	}
	return a.SessionID > b.SessionID
}
