package authz

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BAP-925 / BAP-924: data-driven permission policy.
//
// Tool and effect knowledge lives in JSON data (embedded default, optionally replaced by an
// HMAC-signed administrator override), not in Go switch statements. The engine only matches
// (action, resource) pairs against rules and applies a decision tier:
//
//	allow   - auto-minted
//	approve - requires verified out-of-band human approval
//	deny    - never grantable, not even with human approval
//
// Hard invariants (IsHighRiskEscalationAction, non-reliance) remain in code and always apply
// on top of this policy; the policy can only be stricter than them, never looser.

var (
	ErrActionDenied            = errors.New("permission policy denies this action: it is never grantable to an agent")
	ErrWildcardNotPermitted    = errors.New("wildcard permission is not permitted")
	ErrMintCapExceeded         = errors.New("per-session grant mint cap exceeded")
	ErrSigningSecretMissing    = errors.New("grant signing secret is not configured; refusing to operate (fail-closed)")
	ErrPermissionPolicyInvalid = errors.New("permission policy is invalid")
	ErrPolicySignature         = errors.New("permission policy override signature missing or invalid")
)

// PermissionTier is the decision attached to an (action, resource) pair.
type PermissionTier string

const (
	TierAllow   PermissionTier = "allow"
	TierApprove PermissionTier = "approve"
	TierDeny    PermissionTier = "deny"
)

func tierRank(t PermissionTier) int {
	switch t {
	case TierDeny:
		return 2
	case TierApprove:
		return 1
	}
	return 0
}

// PermissionRule maps action patterns (path.Match globs where ':' is an ordinary character)
// to a tier. A rule with no ResourceMatch applies to in-boundary resources only, unless
// Scope is "any". A rule with ResourceMatch applies only to resources matching a pattern.
type PermissionRule struct {
	ID            string         `json:"id"`
	Tier          PermissionTier `json:"tier"`
	Match         []string       `json:"match"`
	ResourceMatch []string       `json:"resource_match,omitempty"`
	Scope         string         `json:"scope,omitempty"`
	Reason        string         `json:"reason,omitempty"`
}

// Ceiling bounds every grant minted in a session; mints can only be clamped down to it.
type Ceiling struct {
	MaxUsesPerGrant    int `json:"max_uses_per_grant"`
	MaxTTLSeconds      int `json:"max_ttl_seconds"`
	MaxMintsPerSession int `json:"max_mints_per_session"`
}

// PermissionPolicy is the full data-driven policy document.
type PermissionPolicy struct {
	Version           int                 `json:"version"`
	DefaultTier       PermissionTier      `json:"default_tier"`
	BoundaryPrefixes  []string            `json:"boundary_prefixes"`
	ResourceWildcards []string            `json:"resource_wildcards"`
	WildcardNarrowing map[string][]string `json:"wildcard_narrowing"`
	Ceiling           Ceiling             `json:"ceiling"`
	Rules             []PermissionRule    `json:"rules"`
}

// PairDecision is the policy outcome for one (action, resource) pair.
type PairDecision struct {
	Action   string
	Resource string
	Tier     PermissionTier
	RuleID   string
	Reason   string
}

// PolicyEvaluation aggregates per-pair decisions.
type PolicyEvaluation struct {
	Decisions     []PairDecision
	Denied        []PairDecision
	NeedsApproval []PairDecision
}

//go:embed default_permission_policy.json
var defaultPermissionPolicyJSON []byte

var (
	defaultPolicyOnce sync.Once
	defaultPolicy     *PermissionPolicy
	defaultPolicyErr  error
)

// DefaultPermissionPolicy returns the embedded baseline policy.
func DefaultPermissionPolicy() (*PermissionPolicy, error) {
	defaultPolicyOnce.Do(func() {
		defaultPolicy, defaultPolicyErr = ParsePermissionPolicy(defaultPermissionPolicyJSON)
	})
	return defaultPolicy, defaultPolicyErr
}

// ParsePermissionPolicy parses and validates a policy document. Validation is strict and
// fail-closed: an allow default tier, unknown tiers or malformed patterns are rejected.
func ParsePermissionPolicy(data []byte) (*PermissionPolicy, error) {
	var p PermissionPolicy
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPermissionPolicyInvalid, err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrPermissionPolicyInvalid, p.Version)
	}
	if p.DefaultTier != TierApprove && p.DefaultTier != TierDeny {
		return nil, fmt.Errorf("%w: default_tier must be approve or deny, got %q", ErrPermissionPolicyInvalid, p.DefaultTier)
	}
	if len(p.BoundaryPrefixes) == 0 {
		return nil, fmt.Errorf("%w: boundary_prefixes must not be empty", ErrPermissionPolicyInvalid)
	}
	if p.Ceiling.MaxUsesPerGrant <= 0 || p.Ceiling.MaxTTLSeconds <= 0 || p.Ceiling.MaxMintsPerSession <= 0 {
		return nil, fmt.Errorf("%w: ceiling values must be positive", ErrPermissionPolicyInvalid)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("%w: rule %d has no id", ErrPermissionPolicyInvalid, i)
		}
		if r.Tier != TierAllow && r.Tier != TierApprove && r.Tier != TierDeny {
			return nil, fmt.Errorf("%w: rule %s has invalid tier %q", ErrPermissionPolicyInvalid, r.ID, r.Tier)
		}
		if r.Scope != "" && r.Scope != "any" && r.Scope != "workspace" {
			return nil, fmt.Errorf("%w: rule %s has invalid scope %q", ErrPermissionPolicyInvalid, r.ID, r.Scope)
		}
		if len(r.Match) == 0 {
			return nil, fmt.Errorf("%w: rule %s has no match patterns", ErrPermissionPolicyInvalid, r.ID)
		}
		for _, pat := range append(append([]string{}, r.Match...), r.ResourceMatch...) {
			if _, err := path.Match(strings.ToLower(pat), ""); err != nil {
				return nil, fmt.Errorf("%w: rule %s has bad pattern %q: %v", ErrPermissionPolicyInvalid, r.ID, pat, err)
			}
		}
	}
	for k, v := range p.WildcardNarrowing {
		if !strings.Contains(k, "*") {
			return nil, fmt.Errorf("%w: wildcard_narrowing key %q is not a wildcard", ErrPermissionPolicyInvalid, k)
		}
		for _, a := range v {
			if strings.Contains(a, "*") {
				return nil, fmt.Errorf("%w: wildcard_narrowing for %q must not contain wildcards", ErrPermissionPolicyInvalid, k)
			}
		}
	}
	return &p, nil
}

// InBoundary reports whether a resource lies inside the workspace boundary.
func (p *PermissionPolicy) InBoundary(res string) bool {
	r := strings.ToLower(strings.TrimSpace(res))
	if strings.Contains(r, "..") {
		return false // path traversal can never be proven in-boundary by prefix alone
	}
	for _, b := range p.BoundaryPrefixes {
		b = strings.ToLower(strings.TrimSpace(b))
		if r == b || strings.HasPrefix(r, b+"/") {
			return true
		}
	}
	return false
}

// NarrowWildcards expands the policy-defined wildcard narrowings and rejects every other
// wildcard. It returns the resulting actions and whether any narrowing happened.
func (p *PermissionPolicy) NarrowWildcards(actions []string) ([]string, bool, error) {
	var out []string
	narrowed := false
	for _, act := range actions {
		trim := strings.TrimSpace(act)
		if !strings.Contains(trim, "*") {
			out = append(out, trim)
			continue
		}
		repl, ok := p.WildcardNarrowing[strings.ToLower(trim)]
		if !ok || len(repl) == 0 {
			return nil, false, fmt.Errorf("%w: %q", ErrWildcardNotPermitted, trim)
		}
		out = append(out, repl...)
		narrowed = true
	}
	return out, narrowed, nil
}

// NarrowResources maps root-style wildcard resources to the current workspace.
func (p *PermissionPolicy) NarrowResources(resources []string) ([]string, bool) {
	var out []string
	narrowed := false
	for _, res := range resources {
		lower := strings.ToLower(strings.TrimSpace(res))
		hit := false
		for _, w := range p.ResourceWildcards {
			if lower == strings.ToLower(w) {
				hit = true
				break
			}
		}
		if hit {
			out = append(out, "workspace://current")
			narrowed = true
		} else {
			out = append(out, strings.TrimSpace(res))
		}
	}
	return out, narrowed
}

func globAny(patterns []string, s string) bool {
	for _, pat := range patterns {
		if ok, _ := path.Match(strings.ToLower(pat), s); ok {
			return true
		}
	}
	return false
}

func (r *PermissionRule) appliesToResource(p *PermissionPolicy, res string) bool {
	lower := strings.ToLower(strings.TrimSpace(res))
	if len(r.ResourceMatch) > 0 {
		return globAny(r.ResourceMatch, lower)
	}
	if r.Scope == "any" {
		return true
	}
	return p.InBoundary(res)
}

// decide resolves one (action, resource) pair: the most restrictive matching rule wins;
// no match falls back to the default tier (never allow).
func (p *PermissionPolicy) decide(action, resource string) PairDecision {
	a := strings.ToLower(strings.TrimSpace(action))
	best := PairDecision{Action: action, Resource: resource, Tier: p.DefaultTier, RuleID: "default", Reason: "no rule matches; default tier applies"}
	matched := false
	for i := range p.Rules {
		r := &p.Rules[i]
		if !globAny(r.Match, a) || !r.appliesToResource(p, resource) {
			continue
		}
		if !matched || tierRank(r.Tier) > tierRank(best.Tier) {
			best = PairDecision{Action: action, Resource: resource, Tier: r.Tier, RuleID: r.ID, Reason: r.Reason}
			matched = true
		}
	}
	return best
}

// Evaluate decides every (action, resource) pair of a permission ask.
func (p *PermissionPolicy) Evaluate(actions, resources []string) PolicyEvaluation {
	if len(resources) == 0 {
		resources = []string{"workspace://current"}
	}
	var ev PolicyEvaluation
	for _, act := range actions {
		for _, res := range resources {
			d := p.decide(act, res)
			ev.Decisions = append(ev.Decisions, d)
			switch d.Tier {
			case TierDeny:
				ev.Denied = append(ev.Denied, d)
			case TierApprove:
				ev.NeedsApproval = append(ev.NeedsApproval, d)
			}
		}
	}
	return ev
}

// ClampCeiling bounds requested uses and TTL by the policy ceiling.
func (p *PermissionPolicy) ClampCeiling(maxUses int, ttl time.Duration) (int, time.Duration, bool) {
	clamped := false
	if maxUses > p.Ceiling.MaxUsesPerGrant {
		maxUses = p.Ceiling.MaxUsesPerGrant
		clamped = true
	}
	maxTTL := time.Duration(p.Ceiling.MaxTTLSeconds) * time.Second
	if ttl > maxTTL {
		ttl = maxTTL
		clamped = true
	}
	return maxUses, ttl, clamped
}

// FormatPairs renders decisions for error messages and audit reasons.
func FormatPairs(ds []PairDecision) string {
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		parts = append(parts, fmt.Sprintf("%s on %s [rule %s: %s]", d.Action, d.Resource, d.RuleID, d.Reason))
	}
	return strings.Join(parts, "; ")
}

const permissionPolicyOverrideName = "permission-policy.json"

func policyMAC(secret string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// LoadPermissionPolicy returns the effective policy for a ZSP state directory: the signed
// administrator override if present, otherwise the embedded default. An override that is
// unsigned, tampered with, or invalid is a hard error (fail-closed), never silently ignored.
func LoadPermissionPolicy(zspDir, pepSecret string) (*PermissionPolicy, error) {
	overridePath := filepath.Join(zspDir, permissionPolicyOverrideName)
	data, err := os.ReadFile(overridePath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPermissionPolicy()
		}
		return nil, fmt.Errorf("%w: %v", ErrPermissionPolicyInvalid, err)
	}
	if pepSecret == "" {
		return nil, ErrSigningSecretMissing
	}
	sigData, err := os.ReadFile(overridePath + ".sig")
	if err != nil {
		return nil, ErrPolicySignature
	}
	want := policyMAC(pepSecret, data)
	if !hmac.Equal([]byte(strings.TrimSpace(string(sigData))), []byte(want)) {
		return nil, ErrPolicySignature
	}
	return ParsePermissionPolicy(data)
}

// SignPermissionPolicyFile validates srcPath and installs it as the signed override in zspDir.
// This is a human-operator action; the CLI refuses to run it inside an agent broker.
func SignPermissionPolicyFile(zspDir, pepSecret, srcPath string) error {
	if pepSecret == "" {
		return ErrSigningSecretMissing
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	if _, err := ParsePermissionPolicy(data); err != nil {
		return err
	}
	if err := os.MkdirAll(zspDir, 0700); err != nil {
		return err
	}
	dst := filepath.Join(zspDir, permissionPolicyOverrideName)
	if err := writeFileAtomic(dst, data, 0600); err != nil {
		return err
	}
	return writeFileAtomic(dst+".sig", []byte(policyMAC(pepSecret, data)), 0600)
}

// countSessionGrants counts grant files already minted for a session (burned and expired included).
func countSessionGrants(zspDir, sessionID string) int {
	entries, err := os.ReadDir(grantsDirForSession(zspDir, sessionID))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}
