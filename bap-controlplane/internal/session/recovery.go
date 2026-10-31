package session

import (
	"fmt"
	"time"
)

// ResumeMissing never reopens a known ended/revoked session, even if a stop
// arrives concurrently with recovery. Only reporting metadata is reconstructed.
func (s *Store) ResumeMissing(req SessionStartRequest, blocked bool) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.sessions[req.SessionID]; ok {
		if existing.InstanceID != req.InstanceID || existing.Status == "closed" || existing.Status == "revoked" {
			return nil, fmt.Errorf("existing session cannot be replaced or reactivated by resume")
		}
		cp := *existing
		cp.Events = nil
		return &cp, nil
	}
	now := time.Now().UTC()
	status, reason := "active", ""
	if blocked {
		status, reason = "revoked", FrozenReason
	}
	sess := &Session{SessionID: req.SessionID, AppID: req.AppID, InstanceID: req.InstanceID, ResourceID: req.ResourceID,
		UserID: req.UserID, UserEmail: req.UserEmail, SPIFFEID: req.SPIFFEID, WorkstationSPIFFEID: req.WorkstationSPIFFEID,
		SessionSVID: req.SessionSVID,
		Hostname:    req.Hostname, ClientPID: req.ClientPID, AgentName: req.AgentName, StartedAt: now, LastActiveAt: now, Status: status, CloseReason: reason}
	s.sessions[req.SessionID] = sess
	s.order = append(s.order, req.SessionID)
	s.saveSessionToDB(sess)
	cp := *sess
	return &cp, nil
}
