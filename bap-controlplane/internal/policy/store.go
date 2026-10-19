package policy

import (
	"crypto/sha256"
	"encoding/hex"
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
	Version     uint64 `json:"version"`
	Digest      string `json:"digest"`
	PolicyCedar string `json:"policy_cedar"`
	SchemaJSON  string `json:"schema_json,omitempty"`
	KillSwitch  bool   `json:"kill_switch"`
	UpdatedAt   string `json:"updated_at"`
	RiskTier    string `json:"risk_tier,omitempty"`
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
	bundle      Bundle
	tierBundles map[types.RiskTier]Bundle
}

func NewStore(initialCedar, initialSchema string) *Store {
	s := &Store{
		tierBundles: make(map[types.RiskTier]Bundle),
	}
	s.Update(initialCedar, initialSchema, false)
	return s
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

	s.bundle = Bundle{
		Version:     newVersion,
		Digest:      digest,
		PolicyCedar: cedarCode,
		SchemaJSON:  schema,
		KillSwitch:  killSwitch,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
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
