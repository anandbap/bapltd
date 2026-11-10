package identity

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"bap-edge/pkg/types"
)

var (
	ErrInvalidAgentSignature = errors.New("invalid agent cryptographic signature")
	ErrExpiredAgentSVID     = errors.New("agent cryptographic SVID has expired")
	ErrTamperedAgentSVID    = errors.New("agent cryptographic SVID signature mismatch or tampered")
)

// AgentKeypair holds the ephemeral in-memory Ed25519 cryptographic key for an agent session (BAP-915).
type AgentKeypair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateAgentKeypair creates an in-memory ephemeral keypair for an active agent session (BAP-915).
func GenerateAgentKeypair() (*AgentKeypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate agent ed25519 keypair: %w", err)
	}
	return &AgentKeypair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// Sign signs data using the agent's private key.
func (kp *AgentKeypair) Sign(data []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, data)
}

// PublicKeyHex returns the hex-encoded public key.
func (kp *AgentKeypair) PublicKeyHex() string {
	return hex.EncodeToString(kp.PublicKey)
}

// WorkstationIdentityMinter mints and validates human-anchored agent SVIDs (BAP-915).
type WorkstationIdentityMinter struct {
	caSigningSecret []byte
	trustDomain     string
}

// NewWorkstationIdentityMinter initializes the workstation identity minter.
func NewWorkstationIdentityMinter(secret string, trustDomain string) *WorkstationIdentityMinter {
	if secret == "" {
		secret = "bap-workstation-ca-default-signing-key-32bytes"
	}
	if trustDomain == "" {
		trustDomain = "bap.internal"
	}
	return &WorkstationIdentityMinter{
		caSigningSecret: []byte(secret),
		trustDomain:     trustDomain,
	}
}

// MintAgentSVID creates a cryptographically signed workload identity document bound to human identity (BAP-915).
func (m *WorkstationIdentityMinter) MintAgentSVID(
	kp *AgentKeypair,
	humanOwner string,
	humanOIDCSUB string,
	workstationID string,
	sessionID string,
	clientType string,
	ttl time.Duration,
) (*types.CryptographicAgentSVID, error) {
	if kp == nil {
		return nil, errors.New("agent keypair is required to mint SVID")
	}
	if humanOwner == "" {
		humanOwner = "developer@corp.local"
	}
	if workstationID == "" {
		workstationID = "workstation-01"
	}
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	now := time.Now().UTC()
	principalID := fmt.Sprintf("agent-%s-%s", clientType, hex.EncodeToString(kp.PublicKey[:4]))
	spiffeSubject := fmt.Sprintf("spiffe://%s/workstation/%s/principal/%s", m.trustDomain, workstationID, principalID)

	svid := &types.CryptographicAgentSVID{
		Issuer:        fmt.Sprintf("spiffe://%s/ca", m.trustDomain),
		Subject:       spiffeSubject,
		HumanOwner:    humanOwner,
		HumanOIDCSUB:  humanOIDCSUB,
		WorkstationID: workstationID,
		SessionID:     sessionID,
		ClientType:    clientType,
		PublicKeyHex:  kp.PublicKeyHex(),
		IssuedAt:      now,
		ExpiresAt:     now.Add(ttl),
	}

	// Compute issuer signature over canonical SVID claims
	claimBytes := m.canonicalClaimBytes(svid)
	mac := hmac.New(sha256.New, m.caSigningSecret)
	mac.Write(claimBytes)
	svid.IssuerSignature = hex.EncodeToString(mac.Sum(nil))

	return svid, nil
}

// VerifyAgentSVID verifies that an agent SVID was authentically minted and has not expired (BAP-915).
func (m *WorkstationIdentityMinter) VerifyAgentSVID(svid *types.CryptographicAgentSVID) error {
	if svid == nil {
		return errors.New("svid is nil")
	}
	if time.Now().UTC().After(svid.ExpiresAt) {
		return ErrExpiredAgentSVID
	}

	expectedMAC := hmac.New(sha256.New, m.caSigningSecret)
	expectedMAC.Write(m.canonicalClaimBytes(svid))
	expectedSig := hex.EncodeToString(expectedMAC.Sum(nil))

	if !hmac.Equal([]byte(expectedSig), []byte(svid.IssuerSignature)) {
		return ErrTamperedAgentSVID
	}

	return nil
}

func (m *WorkstationIdentityMinter) canonicalClaimBytes(svid *types.CryptographicAgentSVID) []byte {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%d|%d",
		svid.Issuer, svid.Subject, svid.HumanOwner, svid.HumanOIDCSUB,
		svid.WorkstationID, svid.SessionID, svid.ClientType,
		svid.PublicKeyHex, svid.IssuedAt.Unix(), svid.ExpiresAt.Unix())
	return []byte(raw)
}

// VerifyEnvelopeSignature verifies that the task envelope was signed by the agent's private key (BAP-916).
func VerifyEnvelopeSignature(env *types.TaskAuthorizationEnvelope) error {
	pubBytes, err := hex.DecodeString(env.Identity.PublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid agent public key: %w", err)
	}
	sigBytes, err := hex.DecodeString(env.AgentSignature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	hashBytes, err := hex.DecodeString(env.EnvelopeHash)
	if err != nil {
		return fmt.Errorf("invalid envelope hash encoding: %w", err)
	}

	if !ed25519.Verify(pubBytes, hashBytes, sigBytes) {
		return ErrInvalidAgentSignature
	}

	return nil
}

// ComputeEnvelopeHash generates the deterministic SHA-256 hash of the 4-tuple fields (BAP-916).
func ComputeEnvelopeHash(
	identity types.CryptographicAgentSVID,
	auth DelegationIdentityAlias,
	intent TaskIntentAlias,
	perms PermissionAskAlias,
) string {
	payload, _ := json.Marshal(map[string]any{
		"identity":       identity.Subject,
		"human_owner":    identity.HumanOwner,
		"delegation":     auth,
		"intent":         intent,
		"permission_ask": perms,
	})
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// Aliases for clean json serialization
type DelegationIdentityAlias = types.DelegationIdentity
type TaskIntentAlias = types.TaskIntent
type PermissionAskAlias = types.PermissionAsk
