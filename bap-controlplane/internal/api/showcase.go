package api

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"time"

	"bap-controlplane/internal/attestation"
	"bap-controlplane/pkg/types"
)

var showcaseID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

// This endpoint exercises the real binary-image verifier with an unregistered,
// in-memory agent. It cannot enroll, revoke, or mutate a production session.
func (s *Server) handleShowcaseAttestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "Method not allowed")
		return
	}
	var input struct {
		RunID     string `json:"demo_run_id"`
		SessionID string `json:"session_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(w, 400, "Invalid diagnostic request")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || !showcaseID.MatchString(input.RunID) || !showcaseID.MatchString(input.SessionID) {
		writeError(w, 400, "Invalid diagnostic correlation")
		return
	}
	agent := &types.RegisteredAgent{EnvProfile: types.ProfileProd, AllowedBinaryHashes: []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	evidence := []map[string]any{}
	for _, valid := range []bool{true, false} {
		action, hash := "valid", agent.AllowedBinaryHashes[0]
		if !valid {
			action, hash = "invalid", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}
		err := attestation.VerifyBinaryImage(agent, hash)
		decision, explanation, status := "accepted", "Diagnostic allowlisted binary hash accepted.", "participated"
		if err != nil {
			decision, explanation = "rejected", err.Error()
		}
		if (err == nil) != valid {
			status = "failed"
		}
		evidence = append(evidence, map[string]any{
			"demo_run_id": input.RunID, "session_id": input.SessionID, "scenario_id": "attestation", "action_id": action,
			"event_id": "attestation:" + action + ":control-plane/VerifyBinaryImage", "layer": 5, "producer": "control-plane/VerifyBinaryImage",
			"timestamp": time.Now().UTC(), "status": status, "decision": decision, "explanation": explanation, "diagnostic": true,
			"details": map[string]any{"scope": "binary-image verifier only; not TPM/device attestation or live endpoint acceptance", "production_state_mutated": false},
		})
	}
	writeJSON(w, 200, map[string]any{"schema": "bap-defense-showcase/v1", "demo_run_id": input.RunID, "session_id": input.SessionID, "diagnostic": true, "evidence": evidence})
}
