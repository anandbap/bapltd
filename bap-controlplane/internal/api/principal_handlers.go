package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"bap-controlplane/pkg/types"
)

// handlePrincipals handles GET /api/v1/principals (BAP-911).
func (s *Server) handlePrincipals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	principals := s.sessionStore.ListPrincipals()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"principals": principals,
		"total":      len(principals),
	})
}

// handlePrincipalByID handles GET /api/v1/principals/{id} (BAP-911).
func (s *Server) handlePrincipalByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/principals/")
	principalID := strings.TrimSpace(path)
	if principalID == "" {
		http.Error(w, "Principal ID required", http.StatusBadRequest)
		return
	}

	principal, exists := s.sessionStore.GetPrincipal(principalID)
	if !exists {
		http.Error(w, "Principal not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(principal)
}

// handleSessionPrincipal handles GET /api/v1/sessions/{id}/principal (BAP-911).
func (s *Server) handleSessionPrincipal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}
	sessionID := parts[0]

	principal, exists := s.sessionStore.GetSessionPrincipal(sessionID)
	if !exists {
		sess, err := s.sessionStore.Get(sessionID)
		if err != nil || sess == nil {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}
		p, _ := s.sessionStore.RegisterPrincipal(types.AgentPrincipal{
			PrincipalID:    sess.PrincipalID,
			AgentSessionID: sess.SessionID,
			ClientType:     sess.AppID,
			HumanOwner:     sess.UserEmail,
			WorkstationID:  sess.InstanceID,
			PrincipalSVID:  sess.PrincipalSVID,
			Status:         sess.Status,
			Permissions:    []string{"workspace:read", "workspace:write"},
		})
		principal = p
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(principal)
}
