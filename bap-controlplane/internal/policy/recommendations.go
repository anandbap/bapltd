package policy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Recommendations: a registered workstation reports a blocked call it believes is benign; a human
// administrator reviews it. Approval adds the call's canonical EFFECT (for example dev:go:test) to
// that machine's signed policy, so the edge stops asking for a task grant for it. Approvals relax
// the zero-standing-privilege grant requirement only: Cedar invariants (credentials, exfiltration,
// tamper protection) are never relaxed, and some effect classes can never be approved at all.

const (
	RecPending  = "pending"
	RecApproved = "approved"
	RecRejected = "rejected"

	maxRecommendations       = 1000
	maxPendingPerAsset       = 25
	maxRecommendationFieldKB = 2
)

var (
	ErrNotApprovable    = errors.New("this effect class can never be approved from a recommendation")
	ErrTooManyPending   = errors.New("too many pending recommendations for this machine; wait for an administrator to review them")
	ErrRecNotFound      = errors.New("recommendation not found")
	ErrRecAlreadyClosed = errors.New("recommendation was already decided")
)

// Recommendation is one reported call. It carries the canonical effect and a redacted summary,
// never the raw environment.
type Recommendation struct {
	ID            string `json:"id"`
	AssetID       string `json:"asset_id"`
	InstanceID    string `json:"instance_id,omitempty"`
	UserEmail     string `json:"user_email,omitempty"`
	Action        string `json:"action"`   // canonical effect, e.g. dev:go:test
	Zone          string `json:"zone"`     // always "workspace" in this version
	Executable    string `json:"executable,omitempty"`
	CommandHint   string `json:"command_hint,omitempty"` // redacted, truncated
	DenyReason    string `json:"deny_reason,omitempty"`
	Justification string `json:"justification,omitempty"`
	Occurrences   int    `json:"occurrences"`
	Status        string `json:"status"`
	SubmittedAt   string `json:"submitted_at"`
	LastSeenAt    string `json:"last_seen_at"`
	DecidedAt     string `json:"decided_at,omitempty"`
	DecidedBy     string `json:"decided_by,omitempty"`
	DecisionNote  string `json:"decision_note,omitempty"`
}

var actionShape = regexp.MustCompile(`^[a-z0-9][a-z0-9:_\-.]{1,62}$`)

// Substrings that make an effect class unapprovable no matter its prefix.
var neverApprovableParts = []string{
	":delete", ":push", ":install", ":publish", ":deploy", ":upload", ":exfil", ":sudo", ":admin", ":kill",
}

// Prefixes that are never approvable: network, databases, arbitrary interpreters and anything that
// is not a recognised development-loop effect.
var neverApprovablePrefixes = []string{"net:", "http", "db:", "cli:", "sys:", "iam:", "secret", "cred", "system:"}

// Effect classes a recommendation may ever cover: the local development loop.
var approvablePrefixes = []string{"dev:", "fs:file:write", "fs:file:edit", "git:commit", "git:branch:write", "git:add", "git:stash"}

// ApprovableEffect reports whether a canonical action may be approved from a recommendation. The
// edge applies the same rule (bap-edge/internal/authz.ApprovableEffect); keep the two in sync.
func ApprovableEffect(action string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	if !actionShape.MatchString(a) {
		return false
	}
	for _, p := range neverApprovablePrefixes {
		if strings.HasPrefix(a, p) {
			return false
		}
	}
	for _, part := range neverApprovableParts {
		if strings.Contains(a, part) {
			return false
		}
	}
	for _, p := range approvablePrefixes {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	return false
}

func newRecommendationID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "rec-" + hex.EncodeToString(b)
}

func clip(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

// SubmitRecommendation records (or re-counts) a recommendation from an enrolled machine. The same
// pending effect from the same machine is merged, so a developer retrying does not flood admins.
func (s *Store) SubmitRecommendation(r Recommendation) (Recommendation, error) {
	r.Action = strings.ToLower(strings.TrimSpace(r.Action))
	if !ApprovableEffect(r.Action) {
		return Recommendation{}, ErrNotApprovable
	}
	if strings.TrimSpace(r.AssetID) == "" {
		return Recommendation{}, errors.New("asset id required")
	}
	limit := maxRecommendationFieldKB * 1024
	r.Executable = clip(r.Executable, 120)
	r.CommandHint = clip(r.CommandHint, 240)
	r.DenyReason = clip(r.DenyReason, 400)
	r.Justification = clip(r.Justification, limit)
	r.Zone = "workspace"

	now := time.Now().UTC().Format(time.RFC3339)
	s.mu.Lock()
	defer s.mu.Unlock()

	pending := 0
	for i := range s.recommendations {
		e := &s.recommendations[i]
		if e.AssetID != r.AssetID || e.Status != RecPending {
			continue
		}
		pending++
		if e.Action == r.Action {
			e.Occurrences++
			e.LastSeenAt = now
			if r.Justification != "" {
				e.Justification = r.Justification
			}
			_ = s.saveSettingsLocked()
			return *e, nil
		}
	}
	if pending >= maxPendingPerAsset {
		return Recommendation{}, ErrTooManyPending
	}
	r.ID = newRecommendationID()
	r.Status = RecPending
	r.Occurrences = 1
	r.SubmittedAt, r.LastSeenAt = now, now
	s.recommendations = append(s.recommendations, r)
	if len(s.recommendations) > maxRecommendations {
		// Drop the oldest decided entries first; never silently drop a pending one.
		kept := s.recommendations[:0]
		drop := len(s.recommendations) - maxRecommendations
		for _, e := range s.recommendations {
			if drop > 0 && e.Status != RecPending {
				drop--
				continue
			}
			kept = append(kept, e)
		}
		s.recommendations = kept
	}
	_ = s.saveSettingsLocked()
	return r, nil
}

// ListRecommendations returns recommendations newest first. assetID "" lists every machine;
// status "" lists every status.
func (s *Store) ListRecommendations(assetID, status string) []Recommendation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Recommendation{}
	for i := len(s.recommendations) - 1; i >= 0; i-- {
		e := s.recommendations[i]
		if assetID != "" && e.AssetID != assetID {
			continue
		}
		if status != "" && e.Status != status {
			continue
		}
		out = append(out, e)
	}
	return out
}

// DecideRecommendation approves or rejects a pending recommendation. Approving adds the effect to
// the recommending machine's signed policy and advances the policy version so the machine picks
// it up on its next sync (seconds).
func (s *Store) DecideRecommendation(id string, approve bool, by, note string) (Recommendation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.recommendations {
		e := &s.recommendations[i]
		if e.ID != id {
			continue
		}
		if e.Status != RecPending {
			return *e, ErrRecAlreadyClosed
		}
		e.DecidedAt = time.Now().UTC().Format(time.RFC3339)
		e.DecidedBy = clip(by, 120)
		e.DecisionNote = clip(note, 400)
		if approve {
			if !ApprovableEffect(e.Action) {
				return *e, ErrNotApprovable
			}
			e.Status = RecApproved
			s.addApprovedLocked(e.AssetID, e.Action)
			s.bumpLocked()
		} else {
			e.Status = RecRejected
		}
		return *e, s.saveSettingsLocked()
	}
	return Recommendation{}, ErrRecNotFound
}

func (s *Store) addApprovedLocked(assetID, action string) {
	if s.approvedEffects == nil {
		s.approvedEffects = map[string][]string{}
	}
	for _, a := range s.approvedEffects[assetID] {
		if a == action {
			return
		}
	}
	s.approvedEffects[assetID] = append(s.approvedEffects[assetID], action)
	sort.Strings(s.approvedEffects[assetID])
}

// RevokeApprovedEffect removes one approved effect from a machine (admin action).
func (s *Store) RevokeApprovedEffect(assetID, action string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.approvedEffects[assetID]
	for i, a := range list {
		if a == action {
			s.approvedEffects[assetID] = append(list[:i:i], list[i+1:]...)
			if len(s.approvedEffects[assetID]) == 0 {
				delete(s.approvedEffects, assetID)
			}
			s.bumpLocked()
			return true, s.saveSettingsLocked()
		}
	}
	return false, nil
}

// ApprovedEffectsFor returns the effects approved for one machine (sorted copy).
func (s *Store) ApprovedEffectsFor(assetID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.approvedEffects[assetID]...)
}
