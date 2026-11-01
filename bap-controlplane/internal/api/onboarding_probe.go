package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var probeIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func probeReference(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Returns only the caller's bounded probe metadata. No prompt text, native
// session IDs, user identities, commands, grants or other workstation data.
func (s *Server) handleOnboardingProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "Method not allowed")
		return
	}
	identity, err := s.workstationIdentity(r)
	if err != nil {
		writeError(w, 401, "Valid enrolled workstation proof required")
		return
	}
	id := r.URL.Query().Get("probe_id")
	since, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("started_at"))
	now := time.Now().UTC()
	if !probeIDPattern.MatchString(id) || err != nil || since.After(now.Add(5*time.Second)) || now.Sub(since) > 15*time.Minute {
		writeError(w, 400, "Invalid or expired probe interval (maximum 15 minutes)")
		return
	}
	if valid, err := s.auditStore.VerifyAppend(); !valid || err != nil {
		writeError(w, 503, "Retained audit integrity unavailable")
		return
	}
	owned := map[string]bool{}
	restricted := map[string]bool{}
	for _, session := range s.sessionStore.List(0) {
		if session.InstanceID == identity.InstanceID && (session.AppID == "claude-code" || session.AppID == "claude") {
			owned[session.SessionID] = true
			restricted[session.SessionID] = session.Status == "revoked"
		}
	}
	events := s.auditStore.List(1000)
	marker := "BAP-ONBOARDING-" + id
	expectedHash := probeReference(marker + " Please run git status in this fixture repository, then describe the result.")
	matches := map[string]time.Time{}
	for _, event := range events {
		stamp, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil || stamp.Before(since) || stamp.After(now.Add(5*time.Second)) || !owned[event.SessionID] || event.ReportingLayer != "hook" || event.Executable != "user_prompt" || (!strings.Contains(event.UserPrompt, marker) && event.PromptHash != expectedHash) {
			continue
		}
		if matches[event.SessionID].Before(stamp) {
			matches[event.SessionID] = stamp
		}
	}
	result := map[string]any{"probe_id": id, "status": "partial", "prompt_record_observed": false, "policy_record_observed": false, "execution_success_verified": false, "evidence_window_limit": 1000, "server_time": now, "scope": "owned-workstation reported audit evidence; not native-client attestation or business completion"}
	if len(matches) != 1 {
		result["reason"] = "probe_marker_not_observed"
		if len(matches) > 1 {
			result["reason"] = "probe_marker_in_multiple_sessions"
		}
		writeJSON(w, 200, result)
		return
	}
	var sid string
	var promptAt time.Time
	for key, value := range matches {
		sid, promptAt = key, value
	}
	result["prompt_record_observed"] = true
	result["session_reference"] = probeReference(sid)
	result["prompt_observed_at"] = promptAt
	frozen := restricted[sid] || s.registry.WorkstationBlocked(identity.InstanceID, identity.AppID, true) || s.policyStore.GetBundle().KillSwitch
	result["restricted"] = frozen
	latest := time.Time{}
	for _, event := range events {
		stamp, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		decision := strings.ToLower(event.Decision)
		if err != nil || event.SessionID != sid || stamp.Before(since) || stamp.After(now.Add(5*time.Second)) || !stamp.After(latest) || strings.TrimSpace(event.FullCommand) != "git status" || (decision != "allow" && decision != "deny") {
			continue
		}
		if event.ReportingLayer != "broker" && event.ReportingLayer != "hook" && event.ReportingLayer != "shim" {
			continue
		}
		latest = stamp
		result["policy_record_observed"] = true
		result["policy_decision"] = decision
		result["policy_record_reference"] = probeReference(event.EventID)
		result["policy_observed_at"] = stamp
	}
	result["reason"] = "probe_policy_record_not_observed"
	if !latest.IsZero() {
		result["status"] = "policy_record_observed"
		result["reason"] = "local_native_callback_correlation_still_required"
	}
	if result["policy_decision"] == "deny" {
		result["reason"] = "policy_denied"
	}
	if frozen {
		result["reason"] = "session_or_workstation_restricted"
	}
	writeJSON(w, 200, result)
}
