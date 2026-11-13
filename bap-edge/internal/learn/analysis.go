package learn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// PrivateTarget allows tenant-scoped correlation without recording clear targets.
// A tenant-owned secret key is required; plain hashes leak common host/path names.
func PrivateTarget(target string, key []byte) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("target privacy key must contain at least 32 bytes")
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(target))
	return "hmac-sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

type Mismatch struct {
	PredictionID string `json:"prediction_id"`
	Session      string `json:"session"`
	Target       string `json:"target"`
	Reason       string `json:"reason"`
}

// PredictionMismatches compares correlated completed observations. An absent
// trace is unknown, not proof of a classifier false positive. Targets are exact
// boundary identities, never extracted from command text.
func PredictionMismatches(events []Event) []Mismatch {
	groups := map[string][]Event{}
	for _, e := range events {
		if e.PredictionID != "" {
			k := e.Project + "\x00" + e.Session + "\x00" + e.PredictionID
			groups[k] = append(groups[k], e)
		}
	}
	var out []Mismatch
	for _, group := range groups {
		complete := false
		observed := map[string]bool{}
		for _, e := range group {
			if e.Observed && e.Kind == "trace-complete" {
				complete = true
			}
			if e.Observed {
				observed[e.Kind+"\x00"+e.Mode+"\x00"+e.Target] = true
			}
		}
		if !complete {
			continue
		}
		seen := map[string]bool{}
		for _, e := range group {
			k := e.Kind + "\x00" + e.Mode + "\x00" + e.Target
			if e.Source == "hook" && e.Verdict == "deny" && !observed[k] && !seen[k] {
				seen[k] = true
				out = append(out, Mismatch{e.PredictionID, e.Session, e.Target, "hook predicted a denied effect absent from the completed boundary trace"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Session != out[j].Session {
			return out[i].Session < out[j].Session
		}
		if out[i].PredictionID != out[j].PredictionID {
			return out[i].PredictionID < out[j].PredictionID
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// RuleScope holds the rollout state for one exact rule/project pair. Immutable
// rules must never enter complain mode. Promotion requires an entire clean soak.
type RuleScope struct {
	Rule      string    `json:"rule"`
	Project   string    `json:"project"`
	Mode      string    `json:"mode"`
	Since     time.Time `json:"since"`
	Immutable bool      `json:"immutable"`
}

func (s RuleScope) Evaluate(denied bool) (allow, wouldDeny bool) {
	if !denied {
		return true, false
	}
	if s.Mode == "complain" && !s.Immutable {
		return true, true
	}
	return false, false
}

func (s RuleScope) Promote(events []Event, now time.Time, soak time.Duration) (RuleScope, error) {
	if s.Immutable || s.Mode != "complain" || s.Rule == "" || s.Project == "" || s.Since.IsZero() || soak <= 0 || now.Sub(s.Since) < soak {
		return s, fmt.Errorf("promotion requires a scoped complain rule and a completed positive soak period")
	}
	count := 0
	for _, e := range events {
		if e.Rule != s.Rule || e.Project != s.Project || e.Time.Before(s.Since) || e.Time.After(now) {
			continue
		}
		if e.WouldDeny || e.Verdict == "deny" || e.Outcome == "halted" {
			return s, fmt.Errorf("promotion refused: friction observed during soak")
		}
		if e.Observed && (e.Source == "sandbox" || e.Source == "egress-proxy") && e.Kind != "trace-complete" {
			count++
		}
	}
	if count == 0 {
		return s, fmt.Errorf("promotion refused: no observations during soak")
	}
	s.Mode = "enforce"
	s.Since = now.UTC()
	return s, nil
}

type Metrics struct {
	Events               int `json:"events"`
	Sessions             int `json:"sessions"`
	Denials              int `json:"denials"`
	Approvals            int `json:"approvals"`
	WouldDeny            int `json:"would_deny"`
	PredictionMismatches int `json:"prediction_mismatches"`
}

func Summarize(events []Event) Metrics {
	m := Metrics{Events: len(events)}
	sessions := map[string]bool{}
	decisions := map[string]bool{}
	for _, e := range events {
		if e.Session != "" {
			sessions[e.Session] = true
		}
		if e.Verdict == "deny" {
			m.Denials++
		}
		if e.WouldDeny {
			m.WouldDeny++
		}
		if attributedHumanApproval(e) && !decisions[e.DecisionID] {
			decisions[e.DecisionID] = true
			m.Approvals++
		}
	}
	m.Sessions = len(sessions)
	m.PredictionMismatches = len(PredictionMismatches(events))
	return m
}

func attributedHumanApproval(e Event) bool {
	if !e.HumanApproved || e.HumanID == "" || e.DecisionID == "" {
		return false
	}
	return (e.Kind == "egress" && (e.Source == "approval-service" || e.Source == "bap-egress-allow")) || (e.Kind == "policy" && e.Source == "bap-learn")
}
