package session

import (
	"bap-controlplane/internal/audit"
	"bap-controlplane/pkg/types"
	"strings"
	"time"
)

type DefenseLayer struct {
	Layer    int                       `json:"layer"`
	Name     string                    `json:"name"`
	State    string                    `json:"state"`
	Evidence *types.DefenseObservation `json:"evidence,omitempty"`
}

func recordDefense(sess *Session, ev audit.Event) {
	if strings.HasPrefix(ev.SessionID, "diagnostic-") || ev.ReportingLayer == "diagnostic_fixture" {
		return
	}
	observations := ev.DefenseObservations
	if len(observations) == 0 && ev.Decision != "observed" && ev.Executable != "user_prompt" {
		layer := 0
		if ev.ReportingLayer == "hook" {
			layer = 1
		}
		if ev.ReportingLayer == "broker" {
			layer = 2
		}
		if layer != 0 {
			observations = []types.DefenseObservation{{EventID: ev.EventID, ActionID: ev.EventID, Layer: layer, Producer: ev.ReportingLayer, Decision: ev.Decision, Reason: ev.Reason, Timestamp: ev.Timestamp, Scope: "action"}}
		}
	}
	latest := append([]types.DefenseObservation(nil), sess.DefenseObservations...)
	for _, o := range observations {
		stamp, err := time.Parse(time.RFC3339Nano, o.Timestamp)
		if o.Diagnostic || err != nil || stamp.After(time.Now().Add(5*time.Second)) || o.Layer < 1 || o.Layer > 5 || o.EventID == "" || o.Producer == "" || o.ActionID == "" {
			continue
		}
		found := false
		for i, previous := range latest {
			if previous.Layer == o.Layer {
				found = true
				old, _ := time.Parse(time.RFC3339Nano, previous.Timestamp)
				if !stamp.Before(old) {
					latest[i] = o
				}
				break
			}
		}
		if !found {
			latest = append(latest, o)
		}
	}
	sess.DefenseObservations = latest
}

func applyDefense(sess *Session) {
	sess.DefenseObservations = append([]types.DefenseObservation(nil), sess.DefenseObservations...)
	names := []string{"In-harness tool hooks", "Execution broker", "Cryptographic file integrity and pinning", "Anomaly risk engine", "Control-plane attestation"}
	layers := make([]DefenseLayer, 5)
	for i, name := range names {
		layers[i] = DefenseLayer{Layer: i + 1, Name: name, State: "not_observed"}
		for _, o := range sess.DefenseObservations {
			if o.Layer == i+1 {
				copy := o
				layers[i].Evidence = &copy
				layers[i].State = "evaluated"
				switch o.Decision {
				case "CRITICAL", "ELEVATED", "mismatch":
					layers[i].State = "alert"
				case "deny", "blocked", "rejected", "DENIED_POLICY", "DENIED_TAMPER":
					layers[i].State = "blocked"
				}
				break
			}
		}
	}
	if layers[0].Evidence == nil && sess.HooksDisabled {
		layers[0].State = "disabled"
	}
	sess.DefenseLayers = layers
}
