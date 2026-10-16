package authz

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrTokenNotFound        = errors.New("SaaS delegated token not found in registry")
	ErrTokenExpired         = errors.New("SaaS delegated token has expired")
	ErrTokenRevoked         = errors.New("SaaS delegated token has been revoked")
	ErrSessionBindingViolation = errors.New("SaaSTokenSessionBindingViolation: token cannot be reused outside of attested session context")
	ErrScopeNotPermitted    = errors.New("requested scope exceeds token's bound authority")
)

// SaaSTokenBinding represents a third-party or cloud OAuth token bound to an attested BAP session
type SaaSTokenBinding struct {
	TokenID        string    `json:"token_id"`
	SaaSProvider   string    `json:"saas_provider"` // e.g. "salesforce", "workato", "slack", "github"
	BoundSessionID string    `json:"bound_session_id"`
	BoundAgentID   string    `json:"bound_agent_id"`
	BoundUserEmail string    `json:"bound_user_email,omitempty"`
	Scopes         []string  `json:"scopes"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	MaxUses        int       `json:"max_uses,omitempty"`
	UseCount       int       `json:"use_count"`
	Status         string    `json:"status"` // "active", "revoked", "expired"
	RevokeReason   string    `json:"revoke_reason,omitempty"`
}

// SaaSTokenManager governs the issuance, session-binding, and verification of SaaS OAuth tokens
type SaaSTokenManager struct {
	mu     sync.RWMutex
	tokens map[string]*SaaSTokenBinding
}

// NewSaaSTokenManager creates a new SaaSTokenManager
func NewSaaSTokenManager() *SaaSTokenManager {
	return &SaaSTokenManager{
		tokens: make(map[string]*SaaSTokenBinding),
	}
}

// BindToken creates an attested binding between an OAuth/SaaS token and a specific active BAP session
func (m *SaaSTokenManager) BindToken(provider, customTokenID, sessionID, agentID, userEmail string, scopes []string, ttl time.Duration) (*SaaSTokenBinding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.TrimSpace(sessionID) == "" {
		return nil, errors.New("sessionID is required to bind a SaaS token")
	}

	tokenID := customTokenID
	if tokenID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		tokenID = fmt.Sprintf("saas-%s-%s", strings.ToLower(provider), hex.EncodeToString(b))
	}

	if ttl <= 0 {
		ttl = 15 * time.Minute // Short-lived BAP authority invariant
	}

	now := time.Now().UTC()
	binding := &SaaSTokenBinding{
		TokenID:        tokenID,
		SaaSProvider:   strings.ToLower(provider),
		BoundSessionID: sessionID,
		BoundAgentID:   agentID,
		BoundUserEmail: userEmail,
		Scopes:         scopes,
		IssuedAt:       now,
		ExpiresAt:      now.Add(ttl),
		Status:         "active",
		UseCount:       0,
	}

	m.tokens[tokenID] = binding
	return binding, nil
}

// VerifyUsage verifies that the token is used strictly within its bound session context
func (m *SaaSTokenManager) VerifyUsage(tokenID, callingSessionID, requestedScope string) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	binding, exists := m.tokens[tokenID]
	if !exists {
		return false, "TokenNotFound", ErrTokenNotFound
	}

	if binding.Status == "revoked" {
		return false, "TokenRevoked", fmt.Errorf("%w: %s", ErrTokenRevoked, binding.RevokeReason)
	}

	now := time.Now().UTC()
	if now.After(binding.ExpiresAt) {
		binding.Status = "expired"
		return false, "TokenExpired", ErrTokenExpired
	}

	// Invariant: SaaS OAuth tokens cannot be reused outside of attested BAP session contexts
	if binding.BoundSessionID != callingSessionID {
		reason := fmt.Sprintf("SaaSTokenSessionBindingViolation: token bound to session %q cannot be used in session %q",
			binding.BoundSessionID, callingSessionID)
		return false, "SessionBindingViolation", fmt.Errorf("%w: %s", ErrSessionBindingViolation, reason)
	}

	// Verify scope if specified
	if requestedScope != "" {
		scopeAllowed := false
		for _, s := range binding.Scopes {
			if s == "*" || s == requestedScope || strings.HasPrefix(requestedScope, s+":") {
				scopeAllowed = true
				break
			}
		}
		if !scopeAllowed {
			return false, "ScopeExceeded", fmt.Errorf("%w: requested scope %q not in %v", ErrScopeNotPermitted, requestedScope, binding.Scopes)
		}
	}

	binding.UseCount++
	return true, "Authorized", nil
}

// RevokeToken marks a token as revoked across the fleet
func (m *SaaSTokenManager) RevokeToken(tokenID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	binding, exists := m.tokens[tokenID]
	if !exists {
		return ErrTokenNotFound
	}

	binding.Status = "revoked"
	binding.RevokeReason = reason
	return nil
}

// ListBindings returns a snapshot of all token bindings
func (m *SaaSTokenManager) ListBindings() []*SaaSTokenBinding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]*SaaSTokenBinding, 0, len(m.tokens))
	for _, b := range m.tokens {
		cp := *b
		res = append(res, &cp)
	}
	return res
}
