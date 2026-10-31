package session

import (
	"fmt"
	"time"

	"bap-controlplane/internal/audit"
)

// Reserve ownership atomically before ledger admission. Two enrolled machines
// racing to report a previously unknown session cannot mix owners in the ledger.
// This creates reporting metadata only, never a grant or a status restoration.
func (s *Store) ReserveReportingSessions(events []audit.Event, svid func(string) string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ev := range events {
		if ev.SessionID == "" {
			continue
		}
		if existing := s.sessions[ev.SessionID]; existing != nil && existing.InstanceID != ev.InstanceID {
			return fmt.Errorf("audit session belongs to another workstation")
		}
	}
	for _, ev := range events {
		if ev.SessionID == "" {
			continue
		}
		if existing := s.sessions[ev.SessionID]; existing != nil {
			continue
		}
		now := time.Now().UTC()
		at, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
		if err != nil || at.After(now) {
			at = now
		}
		app := ev.Source
		if app == "" {
			app = "agent"
		}
		sess := &Session{SessionID: ev.SessionID, AppID: app, InstanceID: ev.InstanceID, ResourceID: ev.InstanceID,
			WorkstationSPIFFEID: ev.SPIFFEID, SessionSVID: svid(ev.SessionID), UserID: ev.UserID, UserEmail: ev.UserEmail, SPIFFEID: ev.SPIFFEID,
			ClientPID: ev.ClientPID, StartedAt: at, LastActiveAt: at, Status: "active"}
		s.sessions[ev.SessionID] = sess
		s.order = append(s.order, ev.SessionID)
	}
	return nil
}
