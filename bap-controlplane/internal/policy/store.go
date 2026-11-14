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
	ValidUntil            string `json:"valid_until,omitempty"`
	Version               uint64 `json:"version"`
	Digest                string `json:"digest"`
	Signature             string `json:"signature,omitempty"`
	PolicyCedar           string `json:"policy_cedar"`
	SchemaJSON            string `json:"schema_json,omitempty"`
	KillSwitch            bool   `json:"kill_switch"`
	StrictToolEnforcement bool   `json:"strict_tool_enforcement"`    // Tier 2 tool enforcement (Default: false)
	EnforcementTier       string `json:"enforcement_tier,omitempty"` // "tier_1_standard" (default) or "tier_2_strict"
	UpdatedAt             string `json:"updated_at"`
	RiskTier              string `json:"risk_tier,omitempty"`

	// ZSPReadExempt lets plain read-only inspection inside the workspace run without a task
	// grant. Credentials, outside-workspace targets and mutations are never covered.
	ZSPReadExempt bool `json:"zsp_read_exempt"`

	// ApprovedEffects are canonical effects (for example dev:go:test) an administrator approved for
	// THIS machine from a recommendation: they run in the workspace without a task grant. Part of the
	// signed payload; empty (omitted) for machines with no approvals, so their signature is unchanged.
	ApprovedEffects []string `json:"approved_effects,omitempty"`

	// Asset-scoped Ed25519 signature (see CanonicalBundlePayload). Filled per sync response.
	AssetID          string `json:"asset_id,omitempty"`
	SigAlg           string `json:"sig_alg,omitempty"`
	KeyID            string `json:"key_id,omitempty"`
	SignatureEd25519 string `json:"signature_ed25519,omitempty"`

	// KeyChain lets a client pinned to an older key follow a rotation: each link is signed by
	// the previous key (see Signer.Chain). Self-authenticating, so not part of the bundle signature.
	KeyChain []RotationLink `json:"key_chain,omitempty"`
}

type SyncRequest struct {
	SupportsPolicyLease bool   `json:"supports_policy_lease,omitempty"`
	AssetID             string `json:"asset_id,omitempty"` // workstation anchor / device ID the rules apply to
	AgentID             string `json:"agent_id"`
	InstalledVersion    uint64 `json:"installed_version"`
	InstalledDigest     string `json:"installed_digest"`
	InstalledKeyID      string `json:"installed_key_id,omitempty"`
	InstalledAssetID    string `json:"installed_asset_id,omitempty"`
	AgentVersion        string `json:"agent_version,omitempty"`
	RiskTier            string `json:"risk_tier,omitempty"`
}

type SyncResponse struct {
	Directive      SyncDirective `json:"directive"`
	Bundle         *Bundle       `json:"bundle,omitempty"`
	ServerVersion  string        `json:"server_version,omitempty"`
	MinEdgeVersion string        `json:"min_edge_version,omitempty"`
	Message        string        `json:"message,omitempty"`
}

type Store struct {
	maxPolicyAge time.Duration
	mu           sync.RWMutex
	signingKey   []byte
	signer       *Signer
	bundle       Bundle
	tierBundles  map[types.RiskTier]Bundle

	assetOverrides map[string]AssetOverride
	enrolledAssets map[string]string // enrolled workstation instance id -> asset id
	settingsPath   string

	approvedEffects map[string][]string // asset id -> admin-approved effects
	recommendations []Recommendation
}

// SetSigner enables asset-scoped Ed25519 signing of every sync response.
func (s *Store) SetSigner(sg *Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signer = sg
}

// Signer returns the active policy signer (nil when signing is not configured).
func (s *Store) Signer() *Signer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signer
}

// signedFor returns a copy of b stamped and signed for one asset. Caller holds s.mu.
func (s *Store) signedFor(b Bundle, assetID string) Bundle {
	if s.signer == nil {
		return b
	}
	b.AssetID = assetID
	b.SigAlg = SigAlgEd25519
	b.KeyID = s.signer.KeyID()
	if s.maxPolicyAge > 0 {
		b.ValidUntil = time.Now().UTC().Add(s.maxPolicyAge).Format(time.RFC3339)
	}
	b.SignatureEd25519 = s.signer.Sign(CanonicalBundlePayload(b, assetID))
	b.KeyChain = s.signer.Chain()
	return b
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
	return s.updateLocked(cedarCode, schema, killSwitch)
}

// UpdateIfVersion prevents an editor from overwriting a newer policy or freeze decision.
func (s *Store) UpdateIfVersion(cedarCode, schema string, killSwitch bool, expected uint64) (Bundle, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bundle.Version != expected {
		return s.bundle, false
	}
	return s.updateLocked(cedarCode, schema, killSwitch), true
}

func (s *Store) updateLocked(cedarCode, schema string, killSwitch bool) Bundle {
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

	// Developers must be able to have the agent read their own project, so read-only
	// inspection is exempt from task grants by default; an admin can turn that off.
	readExempt := true
	if s.bundle.Version != 0 {
		readExempt = s.bundle.ZSPReadExempt
	}

	s.bundle = Bundle{
		ZSPReadExempt:         readExempt,
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
	_ = s.saveSettingsLocked()
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
	if s.bundle.KillSwitch == killSwitch {
		return
	}
	s.bundle.KillSwitch = killSwitch
	s.bundle.Version++
	s.bundle.Signature = SignBundle(s.bundle.Version, s.bundle.Digest, s.bundle.KillSwitch, s.signingKey)
	s.bundle.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = s.saveSettingsLocked() // keep the persisted version counter monotonic across restarts
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
	s.bundle.Signature = SignBundle(s.bundle.Version, s.bundle.Digest, s.bundle.KillSwitch, s.signingKey)
	s.bundle.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = s.saveSettingsLocked()
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
		signed := s.signedFor(s.applyAssetOverride(s.bundle, req.AssetID), req.AssetID)
		return SyncResponse{
			Directive: DirectiveKillSwitch,
			Bundle:    &signed,
		}
	}

	target := s.bundle
	if req.RiskTier != "" {
		if tb, exists := s.tierBundles[types.RiskTier(req.RiskTier)]; exists {
			// Tier bundles carry their own Cedar rules but inherit fleet-wide enforcement flags.
			tb.StrictToolEnforcement = s.bundle.StrictToolEnforcement
			tb.EnforcementTier = s.bundle.EnforcementTier
			tb.ZSPReadExempt = s.bundle.ZSPReadExempt
			target = tb
		}
	}
	// Machine-scoped overrides win over the fleet default (keyed by hardware asset id).
	target = s.applyAssetOverride(target, req.AssetID)

	// A client is only "current" when it already holds this exact version, digest AND a
	// signed copy for its own asset (a stored copy signed for another asset is not current).
	if s.maxPolicyAge == 0 && req.InstalledVersion == target.Version && req.InstalledDigest == target.Digest &&
		(s.signer == nil || (req.InstalledKeyID == s.signer.KeyID() && req.InstalledAssetID == req.AssetID)) {
		return SyncResponse{
			Directive: DirectiveCurrent,
		}
	}

	signed := s.signedFor(target, req.AssetID)
	return SyncResponse{
		Directive: DirectiveUpdateRequired,
		Bundle:    &signed,
	}
}
