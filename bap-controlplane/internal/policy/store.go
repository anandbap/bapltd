package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"bap-controlplane/pkg/types"
)

type SyncDirective string

const (
	DirectiveCurrent        SyncDirective = "CURRENT"
	DirectiveUpdateRequired SyncDirective = "UPDATE_REQUIRED"
	DirectiveKillSwitch     SyncDirective = "KILL_SWITCH"
)

type Bundle struct {
	Version               uint64 `json:"version"`
	Digest                string `json:"digest"`
	Signature             string `json:"signature,omitempty"`
	PolicyCedar           string `json:"policy_cedar"`
	SchemaJSON            string `json:"schema_json,omitempty"`
	KillSwitch            bool   `json:"kill_switch"`
	StrictToolEnforcement bool   `json:"strict_tool_enforcement"` // Tier 2 tool enforcement (Default: false)
	EnforcementTier       string `json:"enforcement_tier,omitempty"` // "tier_1_standard" (default) or "tier_2_strict"
	UpdatedAt             string `json:"updated_at"`
	RiskTier              string `json:"risk_tier,omitempty"`
}

type SyncRequest struct {
	AgentID          string `json:"agent_id"`
	InstalledVersion uint64 `json:"installed_version"`
	InstalledDigest  string `json:"installed_digest"`
	AgentVersion     string `json:"agent_version,omitempty"`
	RiskTier         string `json:"risk_tier,omitempty"`
}

type SyncResponse struct {
	Directive      SyncDirective `json:"directive"`
	Bundle         *Bundle       `json:"bundle,omitempty"`
	ServerVersion  string        `json:"server_version,omitempty"`
	MinEdgeVersion string        `json:"min_edge_version,omitempty"`
	Message        string        `json:"message,omitempty"`
}

type Store struct {
	mu          sync.RWMutex
	signingKey  []byte
	bundle      Bundle
	tierBundles map[types.RiskTier]Bundle
}

// SignBundle computes an HMAC-SHA256 signature over version:digest:kill_switch
func SignBundle(version uint64, digest string, killSwitch bool, key []byte) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	payload := fmt.Sprintf("bap-policy-v1:%d:%s:%t", version, digest, killSwitch)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature validates a bundle's signature
func VerifySignature(version uint64, digest string, killSwitch bool, signature string, key []byte) bool {
	if len(key) == 0 {
		return true
	}
	if signature == "" {
		return false
	}
	expected := SignBundle(version, digest, killSwitch, key)
	return hmac.Equal([]byte(signature), []byte(expected))
}

func NewStore(initialCedar, initialSchema string) *Store {
	return NewStoreWithKey(initialCedar, initialSchema, nil)
}

func NewStoreWithKey(initialCedar, initialSchema string, signingKey []byte) *Store {
	s := &Store{
		signingKey:  signingKey,
		tierBundles: make(map[types.RiskTier]Bundle),
	}
	s.Update(initialCedar, initialSchema, false)
	return s
}

func (s *Store) SetSigningKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signingKey = key
	if s.bundle.Digest != "" {
		s.bundle.Signature = SignBundle(s.bundle.Version, s.bundle.Digest, s.bundle.KillSwitch, s.signingKey)
	}
}

func (s *Store) Update(cedarCode, schema string, killSwitch bool) Bundle {
	s.mu.Lock()
	defer s.mu.Unlock()

	hasher := sha256.New()
	hasher.Write([]byte(cedarCode))
	if schema != "" {
		hasher.Write([]byte(schema))
	}
	digest := hex.EncodeToString(hasher.Sum(nil))

	newVersion := s.bundle.Version + 1
	if s.bundle.Version == 0 {
		newVersion = 1
	}

	strict := s.bundle.StrictToolEnforcement
	tier := s.bundle.EnforcementTier
	if tier == "" {
		if strict {
			tier = "tier_2_strict"
		} else {
			tier = "tier_1_standard"
		}
	}

	sig := SignBundle(newVersion, digest, killSwitch, s.signingKey)

	s.bundle = Bundle{
		Version:               newVersion,
		Digest:                digest,
		Signature:             sig,
		PolicyCedar:           cedarCode,
		SchemaJSON:            schema,
		KillSwitch:            killSwitch,
		StrictToolEnforcement: strict,
		EnforcementTier:       tier,
		UpdatedAt:             time.Now().UTC().Format(time.RFC3339),
	}
	return s.bundle
}

// SetTierPolicy updates or defines an explicit policy bundle tailored for a specific agent risk tier (BAP-733).
func (s *Store) SetTierPolicy(tier types.RiskTier, cedarCode, schema string) Bundle {
	s.mu.Lock()
	defer s.mu.Unlock()

	hasher := sha256.New()
	hasher.Write([]byte(cedarCode))
	if schema != "" {
		hasher.Write([]byte(schema))
	}
	digest := hex.EncodeToString(hasher.Sum(nil))

	bundle := Bundle{
		Version:     s.bundle.Version,
		Digest:      digest,
		PolicyCedar: cedarCode,
		SchemaJSON:  schema,
		KillSwitch:  false,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
		RiskTier:    string(tier),
	}
	s.tierBundles[tier] = bundle
	return bundle
}

// GetPolicyBundleForTier retrieves the designated policy bundle for an agent's evaluated risk tier (BAP-733).
func (s *Store) GetPolicyBundleForTier(tier types.RiskTier) Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if tb, exists := s.tierBundles[tier]; exists {
		return tb
	}
	return s.bundle
}

func (s *Store) SetKillSwitch(killSwitch bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle.KillSwitch = killSwitch
	s.bundle.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
}

func (s *Store) SetStrictToolEnforcement(strict bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle.StrictToolEnforcement = strict
	if strict {
		s.bundle.EnforcementTier = "tier_2_strict"
	} else {
		s.bundle.EnforcementTier = "tier_1_standard"
	}
	s.bundle.Version++
	s.bundle.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
}

func (s *Store) IsStrictToolEnforcement() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundle.StrictToolEnforcement
}

func (s *Store) GetBundle() Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundle
}

func (s *Store) Sync(req SyncRequest) SyncResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle.KillSwitch {
		return SyncResponse{
			Directive: DirectiveKillSwitch,
			Bundle:    &s.bundle,
		}
	}

	targetBundle := &s.bundle
	if req.RiskTier != "" {
		if tb, exists := s.tierBundles[types.RiskTier(req.RiskTier)]; exists {
			targetBundle = &tb
		}
	}

	if req.InstalledVersion == targetBundle.Version && req.InstalledDigest == targetBundle.Digest {
		return SyncResponse{
			Directive: DirectiveCurrent,
		}
	}

	return SyncResponse{
		Directive: DirectiveUpdateRequired,
		Bundle:    targetBundle,
	}
}
