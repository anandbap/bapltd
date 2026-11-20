package api

import (
	"bap-controlplane/internal/audit"
	"bap-controlplane/pkg/types"
	"fmt"
	"time"
)

func filterLocalDefense(ev audit.Event) []types.DefenseObservation {
	result := []types.DefenseObservation{}
	for _, o := range ev.DefenseObservations {
		if o.Layer < 1 || o.Layer > 4 || o.EventID == "" || o.ActionID == "" || o.Producer == "" {
			continue
		}
		if o.Layer == 1 && ev.ReportingLayer != "hook" {
			continue
		}
		if o.Layer >= 2 && ev.ReportingLayer != "broker" {
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, o.Timestamp); err != nil {
			continue
		}
		result = append(result, o)
		if len(result) == 128 {
			break
		}
	}
	return result
}

// Only the real verifier's call sites emit this evidence. Caller-supplied
// audit ingestion cannot impersonate layer 5.
func (s *Server) recordImageAttestation(agent *types.RegisteredAgent, sessionID string, verification error) {
	if s.auditStore == nil {
		return
	}
	now := time.Now().UTC()
	decision, reason := "passed", "Binary image verifier accepted the candidate hash"
	if verification != nil {
		decision, reason = "rejected", verification.Error()
	}
	if sessionID != "" {
		sess, err := s.sessionStore.GetSummary(sessionID)
		if err != nil || sess.InstanceID != agent.InstanceID {
			sessionID = ""
		}
	}
	id := fmt.Sprintf("attestation-%d-%s", now.UnixNano(), agent.AgentID)
	o := types.DefenseObservation{EventID: id, ActionID: id, Layer: 5, Producer: "control-plane/VerifyBinaryImage", Decision: decision, Reason: reason, Timestamp: now.Format(time.RFC3339Nano), Scope: "workstation"}
	ev := audit.Event{EventID: id, SessionID: sessionID, AgentID: agent.AgentID, InstanceID: agent.InstanceID, ReportingLayer: "attestation", Source: "control-plane", Executable: "defense_attestation", Decision: "observed", Timestamp: o.Timestamp, DefenseObservations: []types.DefenseObservation{o}}
	accepted, err := s.auditStore.IngestAccepted([]audit.Event{ev})
	if err != nil {
		return
	}
	for _, event := range accepted {
		if event.SessionID != "" {
			s.sessionStore.RecordEvent(event.SessionID, event)
		}
	}
}
