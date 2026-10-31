package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

func (s *Server) recordRecoveryRestore(scope, id string, restored bool) {
	if id == "" && scope != "fleet" {
		return
	}
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	if s.recoveryRestores == nil {
		s.recoveryRestores = make(map[string]bool)
	}
	if restored {
		s.recoveryRestores[scope+":"+id] = true
	} else {
		delete(s.recoveryRestores, scope+":"+id)
	}
}

func (s *Server) recoveryRestorations() (sessions, agents []string, fleet bool) {
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	for key := range s.recoveryRestores {
		if strings.HasPrefix(key, "session:") {
			sessions = append(sessions, strings.TrimPrefix(key, "session:"))
		}
		if strings.HasPrefix(key, "agent:") {
			agents = append(agents, strings.TrimPrefix(key, "agent:"))
		}
	}
	return sessions, agents, s.recoveryRestores["fleet:"]
}

// Recovery restores reporting identity, never issues execution grants. The
// enrolled workstation proof must survive deployment (stable BAP_SECRET_KEY).
func (s *Server) handleSessionResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "Method not allowed")
		return
	}
	var req struct {
		session.SessionStartRequest
		LocalBlocked bool `json:"local_blocked"`
		LocalFrozen  bool `json:"local_frozen"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, 400, "Invalid resume payload")
		return
	}
	claims, err := s.workstationIdentity(r)
	if err != nil || claims.InstanceID == "" || claims.InstanceID != req.InstanceID || claims.SessionID != "" || claims.Action != "" || claims.Resource != "" {
		writeError(w, 401, "Valid enrolled workstation proof matching instance_id required")
		return
	}
	if req.SessionID == "" || req.AppID == "" || req.ClientPID <= 0 {
		writeError(w, 400, "Session identity, app_id and live client_pid required")
		return
	}
	if s.policyStore.GetBundle().KillSwitch || s.sessionStore.IsUserRevoked(claims.UserEmail) {
		writeError(w, 403, "Recovery blocked by administrative policy")
		return
	}
	for _, a := range s.registry.List() {
		if a.InstanceID == claims.InstanceID || a.AgentID == claims.Sub || a.SPIFFEID == claims.Sub {
			if a.Status == types.StatusRevoked || a.Status == types.StatusDeregistered || a.Status == types.StatusQuarantined {
				writeError(w, 403, "Workstation authority is blocked")
				return
			}
		}
	}
	if existing, err := s.sessionStore.Get(req.SessionID); err == nil {
		if existing.InstanceID != req.InstanceID || existing.Status == "closed" || existing.Status == "revoked" {
			writeError(w, 409, "Existing session cannot be replaced or reactivated by resume")
			return
		}
		writeJSON(w, 200, map[string]any{"status": "alive", "reporting_only": true})
		return
	}
	// Ignore client-supplied grant/lineage fields and bind identity to the proof.
	start := session.SessionStartRequest{SessionID: req.SessionID, AppID: req.AppID, InstanceID: claims.InstanceID, ResourceID: claims.InstanceID,
		UserID: claims.Sub, UserEmail: claims.UserEmail, SPIFFEID: claims.SPIFFEID, WorkstationSPIFFEID: claims.SPIFFEID, Hostname: req.Hostname, ClientPID: req.ClientPID, AgentName: req.AgentName,
		SessionSVID: s.recoveredSessionSVID(claims.InstanceID, claims.SPIFFEID, req.SessionID)}
	sess, err := s.sessionStore.ResumeMissing(start, req.LocalBlocked || req.LocalFrozen)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	station := s.registry.EnsureSessionAgent(claims.AppID, claims.InstanceID, claims.SPIFFEID, claims.UserEmail, req.Hostname, claims.AgentName)
	if req.LocalFrozen && station != nil {
		_, _ = s.registry.QuarantineTarget(station.AgentID, "Recovered cached workstation freeze")
	}
	writeJSON(w, 200, map[string]any{"status": sess.Status, "reporting_only": true, "session_id": sess.SessionID})
}
