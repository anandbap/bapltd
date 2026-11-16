package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"bap-controlplane/pkg/types"
)

// handleZSPGrantsSync ingests and persists ZSP task grants and receipts into SQLite.
func (s *Server) handleZSPGrantsSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.sessionStore == nil {
		writeError(w, http.StatusServiceUnavailable, "Session store unavailable")
		return
	}

	var payload json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	var grants []*types.TaskGrant
	if err := json.Unmarshal(payload, &grants); err != nil {
		var single types.TaskGrant
		if errSingle := json.Unmarshal(payload, &single); errSingle != nil {
			writeError(w, http.StatusBadRequest, "Payload must be a TaskGrant or array of TaskGrants")
			return
		}
		grants = []*types.TaskGrant{&single}
	}

	if err := s.sessionStore.SaveZSPGrants(grants); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist ZSP grants: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "synced",
		"count":  len(grants),
	})
}

// handleZSPGrants lists grants with rich details, optionally filtered by session_id.
func (s *Server) handleZSPGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.sessionStore == nil {
		writeError(w, http.StatusServiceUnavailable, "Session store unavailable")
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	limit := 100
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}

	grants, err := s.sessionStore.ListZSPGrants(sessionID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list ZSP grants: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(grants),
		"grants": grants,
	})
}

// handleZSPGrantByID retrieves a single grant and its full details by ID.
func (s *Server) handleZSPGrantByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.sessionStore == nil {
		writeError(w, http.StatusServiceUnavailable, "Session store unavailable")
		return
	}

	grantID := strings.TrimPrefix(r.URL.Path, "/api/v1/zsp/grants/")
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		writeError(w, http.StatusBadRequest, "grant_id is required")
		return
	}

	grant, err := s.sessionStore.GetZSPGrant(grantID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Grant not found: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, grant)
}
