package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/policy"
)

// Policy recommendations.
//
//	POST /api/v1/policy/recommendations          enrolled workstation reports a blocked call it believes is benign
//	GET  /api/v1/policy/recommendations          enrolled workstation lists ITS OWN recommendations and their status
//	GET  /api/v1/admin/policy/recommendations    admin queue (?status=pending|approved|rejected)
//	POST /api/v1/admin/policy/recommendations/{id}/approve|reject   admin decision {"note": "..."}
//	DELETE /api/v1/admin/policy/approvals?asset_id=..&action=..     admin revokes an approved effect
//
// This is not an open API: the submit and list routes require a valid enrolled-workstation credential
// (the same proof every other edge call uses); the decision routes require the administrator token.
// An approval relaxes the task-grant requirement for exactly one canonical effect on exactly one
// machine, through the signed per-asset policy bundle that the edge verifies.

const maxRecommendationBody = 16 << 10

func (s *Server) handleWorkstationRecommendations(w http.ResponseWriter, r *http.Request) {
	claims, err := s.workstationIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Valid enrolled workstation credential required")
		return
	}
	asset, ok := s.policyStore.EnrolledAsset(claims.InstanceID)
	if !ok {
		writeError(w, http.StatusConflict, "this machine has not synced policy yet; run `bapedge sync` and retry")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"asset_id": asset, "recommendations": s.policyStore.ListRecommendations(asset, "")})
	case http.MethodPost:
		var req struct {
			Action        string `json:"action"`
			Executable    string `json:"executable"`
			CommandHint   string `json:"command_hint"`
			DenyReason    string `json:"deny_reason"`
			Justification string `json:"justification"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRecommendationBody)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
			return
		}
		rec, err := s.policyStore.SubmitRecommendation(policy.Recommendation{
			AssetID: asset, InstanceID: claims.InstanceID, UserEmail: claims.UserEmail,
			Action: req.Action, Executable: req.Executable, CommandHint: req.CommandHint,
			DenyReason: req.DenyReason, Justification: req.Justification,
		})
		switch {
		case errors.Is(err, policy.ErrNotApprovable):
			writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("%q is not an effect class that can be approved from a recommendation (network, deletion, publishing, databases, arbitrary interpreters and credentials never can). Use a task grant instead.", strings.TrimSpace(req.Action)))
			return
		case errors.Is(err, policy.ErrTooManyPending):
			writeError(w, http.StatusTooManyRequests, err.Error())
			return
		case err != nil:
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.recordPolicyAdmin("workstation:"+claims.InstanceID, "POLICY_RECOMMENDATION",
			fmt.Sprintf("recommend --asset=%s --effect=%s", asset, rec.Action), "SUBMITTED",
			fmt.Sprintf("Recommendation %s: %s (seen %d time(s))", rec.ID, rec.Action, rec.Occurrences))
		writeJSON(w, http.StatusAccepted, rec)
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

const adminRecPrefix = "/api/v1/admin/policy/recommendations"

func (s *Server) handleAdminRecommendations(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminCaller(r) {
		writeError(w, http.StatusUnauthorized, "Administrator authentication required")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, adminRecPrefix), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		if status != "" && status != policy.RecPending && status != policy.RecApproved && status != policy.RecRejected && status != policy.RecRevoked {
			writeError(w, http.StatusBadRequest, "status must be pending, approved or rejected")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"recommendations": s.policyStore.ListRecommendations("", status)})
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || (parts[1] != "approve" && parts[1] != "reject") || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "use POST "+adminRecPrefix+"/{id}/approve or /reject")
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body)
	approve := parts[1] == "approve"
	rec, err := s.policyStore.DecideRecommendation(parts[0], approve, "admin", body.Note)
	switch {
	case errors.Is(err, policy.ErrRecNotFound):
		writeError(w, http.StatusNotFound, "recommendation not found")
		return
	case errors.Is(err, policy.ErrRecAlreadyClosed):
		writeError(w, http.StatusConflict, "recommendation was already decided")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "Failed to persist decision: "+err.Error())
		return
	}
	verb := "REJECTED"
	if approve {
		verb = "APPROVED"
	}
	s.recordPolicyAdmin("admin", "POLICY_RECOMMENDATION",
		fmt.Sprintf("recommendation --id=%s --%s --asset=%s --effect=%s", rec.ID, strings.ToLower(verb), rec.AssetID, rec.Action), verb,
		fmt.Sprintf("Recommendation %s %s for %s on %s", rec.ID, strings.ToLower(verb), rec.Action, rec.AssetID))
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleAdminApprovals(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminCaller(r) {
		writeError(w, http.StatusUnauthorized, "Administrator authentication required")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	asset := strings.TrimSpace(r.URL.Query().Get("asset_id"))
	action := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action")))
	if !validAssetID(asset) || action == "" {
		writeError(w, http.StatusBadRequest, "asset_id and action are required")
		return
	}
	removed, err := s.policyStore.RevokeApprovedEffect(asset, action)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist policy settings: "+err.Error())
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "no such approved effect for that asset")
		return
	}
	s.recordPolicyAdmin("admin", "POLICY_RECOMMENDATION", fmt.Sprintf("approval --asset=%s --effect=%s --revoke", asset, action), "REVOKED",
		fmt.Sprintf("Approved effect %s revoked for %s", action, asset))
	writeJSON(w, http.StatusOK, s.policyStore.Settings())
}

func (s *Server) recordPolicyAdmin(source, executable, command, decision, reason string) {
	if s.auditStore == nil {
		return
	}
	_, _ = s.auditStore.Ingest([]audit.Event{{
		Source: source, Executable: executable, FullCommand: command,
		Decision: decision, Reason: reason, Timestamp: time.Now().UTC().Format(time.RFC3339),
	}})
}
