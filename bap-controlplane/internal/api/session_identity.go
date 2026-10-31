package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/session"
)

var errWorkstationProof = errors.New("invalid workstation credential")

func (s *Server) workstationIdentity(r *http.Request) (*authz.GrantClaims, error) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return nil, errWorkstationProof
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := s.minter.Verify(token)
	if err != nil {
		return nil, err
	}
	// Legacy enrollment tokens were minted for one year without token_use.
	legacy := claims.TokenUse == "" && claims.Iat > 0 && claims.Exp-claims.Iat >= 300*24*60*60
	if claims.Iss != "bap-controlplane" || claims.InstanceID == "" || claims.Sub == "" || (claims.TokenUse != "workstation" && !legacy) || claims.SessionID != "" || claims.Action != "" || claims.Resource != "" {
		return nil, errWorkstationProof
	}
	if s.sessionStore.IsUserRevoked(claims.UserEmail) {
		return nil, errWorkstationProof
	}
	if s.registry.WorkstationBlocked(claims.InstanceID, claims.AppID, false) {
		return nil, errWorkstationProof
	}
	return claims, nil
}

// Authenticates first, then binds all session mutations to the enrolled machine.
// Explicit administrative callers remain authorized for operator/demo tooling.
func (s *Server) requireSessionIdentity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next(w, r)
			return
		}
		if s.isAdminCaller(r) {
			next(w, r)
			return
		}
		claims, err := s.workstationIdentity(r)
		if err != nil {
			writeError(w, 401, "Valid enrolled workstation credential required")
			return
		}
		if s.registry.WorkstationBlocked(claims.InstanceID, claims.AppID, true) {
			if strings.HasSuffix(r.URL.Path, "/heartbeat") {
				writeJSON(w, 200, map[string]any{"status": "quarantined", "action": "quarantine", "reason": "Workstation frozen by administrator"})
			} else {
				writeError(w, 403, "Workstation frozen by administrator")
			}
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
		if err != nil {
			writeError(w, 400, "Invalid or oversized request body")
			return
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			writeError(w, 400, "Invalid session payload")
			return
		}
		text := func(key string) string { var value string; _ = json.Unmarshal(object[key], &value); return value }
		sid, aid := text("session_id"), text("agent_id")
		if instance := text("instance_id"); instance != "" && instance != claims.InstanceID {
			writeError(w, 403, "Workstation identity mismatch")
			return
		}
		if sid != "" {
			if sess, err := s.sessionStore.GetSummary(sid); err == nil {
				if sess.InstanceID != claims.InstanceID {
					writeError(w, 403, "Session belongs to another workstation")
					return
				}
			} else if r.URL.Path != "/api/v1/sessions/start" {
				writeError(w, 404, "Session not found; authenticated resume required")
				return
			}
		}
		if sid == "" && aid != "" {
			if sess, err := s.sessionStore.GetSummary(aid); err == nil && sess.InstanceID != claims.InstanceID {
				writeError(w, 403, "Session belongs to another workstation")
				return
			}
		}
		if aid != "" {
			if agent, err := s.registry.Get(aid); err == nil && agent.InstanceID != claims.InstanceID {
				writeError(w, 403, "Agent belongs to another workstation")
				return
			}
		}
		if r.URL.Path == "/api/v1/sessions/start" {
			if sid == "" {
				sid = session.GenerateSessionID("sess-" + text("app_id"))
				object["session_id"], _ = json.Marshal(sid)
			}
			if resource := text("resource_id"); resource != "" && resource != claims.InstanceID {
				writeError(w, 403, "Workstation resource mismatch")
				return
			}
			for key, value := range map[string]string{"instance_id": claims.InstanceID, "resource_id": claims.InstanceID, "user_id": claims.Sub, "user_email": claims.UserEmail, "spiffe_id": claims.SPIFFEID, "workstation_spiffe_id": claims.SPIFFEID} {
				object[key], _ = json.Marshal(value)
			}
			identity := claims.SPIFFEID
			if identity == "" {
				identity = "spiffe://" + s.registry.TrustDomain() + "/workstation/" + url.PathEscape(claims.InstanceID)
			}
			object["session_svid"], _ = json.Marshal(identity + "/session/" + url.PathEscape(sid))
		}
		for key, value := range map[string]string{"user_id": claims.Sub, "user_email": claims.UserEmail, "spiffe_id": claims.SPIFFEID} {
			object[key], _ = json.Marshal(value)
		}
		if strings.HasSuffix(r.URL.Path, "/activity/ingest") {
			object["agent_id"], _ = json.Marshal(claims.AgentID)
			object["runtime_id"], _ = json.Marshal(claims.InstanceID)
		}
		raw, _ = json.Marshal(object)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next(w, r)
	}
}

func (s *Server) recoveredSessionSVID(instance, spiffe, id string) string {
	if spiffe == "" {
		spiffe = "spiffe://" + s.registry.TrustDomain() + "/workstation/" + url.PathEscape(instance)
	}
	return spiffe + "/session/" + url.PathEscape(id)
}
