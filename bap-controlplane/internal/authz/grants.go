package authz

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"bap-controlplane/pkg/types"
)

type grantUsage struct {
	consumedAt time.Time
	usesCount  int
}

type TokenMinter struct {
	signingKey     []byte
	defaultTTL     time.Duration
	mu             sync.Mutex
	consumedGrants map[string]*grantUsage
}

func NewTokenMinter(secretKey string, defaultTTL time.Duration) *TokenMinter {
	if defaultTTL <= 0 {
		defaultTTL = 30 * time.Minute
	}
	tm := &TokenMinter{
		signingKey:     []byte(secretKey),
		defaultTTL:     defaultTTL,
		consumedGrants: make(map[string]*grantUsage),
	}
	go tm.cleanupLoop()
	return tm
}

func (tm *TokenMinter) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		tm.mu.Lock()
		now := time.Now()
		for id, usage := range tm.consumedGrants {
			if now.Sub(usage.consumedAt) > 2*tm.defaultTTL {
				delete(tm.consumedGrants, id)
			}
		}
		tm.mu.Unlock()
	}
}

type GrantClaims struct {
	GrantID       string                  `json:"jti"`
	Sub           string                  `json:"sub"`
	AppID         string                  `json:"app_id"`
	InstanceID    string                  `json:"instance_id,omitempty"`
	SPIFFEID      string                  `json:"spiffe_id,omitempty"`
	AgentName     string                  `json:"agent_name"`
	EnvProfile    string                  `json:"env_profile"`
	BinaryHash    string                  `json:"binary_hash"`
	SessionID     string                  `json:"session_id,omitempty"`
	Action        string                  `json:"action,omitempty"`
	Resource      string                  `json:"resource,omitempty"`
	Constraints   *types.GrantConstraints `json:"constraints,omitempty"`
	PolicyVersion string                  `json:"policy_version,omitempty"`
	Scopes        []string                `json:"scopes"`
	UserEmail     string                  `json:"user_email,omitempty"`
	Department    string                  `json:"department,omitempty"`
	Groups        []string                `json:"groups,omitempty"`
	AuthMode      string                  `json:"auth_mode,omitempty"`
	IdPProvider   string                  `json:"idp_provider,omitempty"`
	Iss           string                  `json:"iss"`
	Aud           string                  `json:"aud"`
	Iat           int64                   `json:"iat"`
	Exp           int64                   `json:"exp"`
}

// Mint maintains backward compatibility with legacy calls.
func (tm *TokenMinter) Mint(agent *types.RegisteredAgent, candidateHash string, requestedScopes []string) (string, time.Time, error) {
	token, exp, _, err := tm.MintWithDetails(agent, candidateHash, requestedScopes, "", "", "", nil, "")
	return token, exp, err
}

// MintWithDetails mints a full BAP-407 Bounded Grant containing explicit session, action, resource, constraints, and policy version.
func (tm *TokenMinter) MintWithDetails(
	agent *types.RegisteredAgent,
	candidateHash string,
	requestedScopes []string,
	sessionID string,
	action string,
	resource string,
	constraints *types.GrantConstraints,
	policyVersion string,
) (string, time.Time, string, error) {
	now := time.Now()
	expiresAt := now.Add(tm.defaultTTL)

	scopes := agent.PermittedScopes
	if len(scopes) == 0 {
		scopes = []string{"cli:exec", "zero-trust"}
	}
	if len(requestedScopes) > 0 {
		for _, requested := range requestedScopes {
			allowed := false
			for _, permitted := range scopes {
				if permitted == requested || permitted == "*" || (strings.HasSuffix(permitted, "*") && strings.HasPrefix(requested, strings.TrimSuffix(permitted, "*"))) {
					allowed = true
					break
				}
			}
			if !allowed {
				return "", time.Time{}, "", fmt.Errorf("requested scope %q is not permitted", requested)
			}
		}
		scopes = requestedScopes
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return "", time.Time{}, "", fmt.Errorf("failed to generate random token id: %w", err)
	}
	grantID := fmt.Sprintf("grant-%x", idBytes)

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	sub := agent.AgentID
	if agent.SPIFFEID != "" {
		sub = agent.SPIFFEID
	}

	claims := GrantClaims{
		GrantID:       grantID,
		Sub:           sub,
		AppID:         agent.AppID,
		InstanceID:    agent.InstanceID,
		SPIFFEID:      agent.SPIFFEID,
		AgentName:     agent.AgentName,
		EnvProfile:    string(agent.EnvProfile),
		BinaryHash:    candidateHash,
		SessionID:     sessionID,
		Action:        action,
		Resource:      resource,
		Constraints:   constraints,
		PolicyVersion: policyVersion,
		Scopes:        scopes,
		UserEmail:     agent.UserEmail,
		Department:    agent.Department,
		Groups:        agent.Groups,
		AuthMode:      agent.AuthMode,
		IdPProvider:   agent.IdPProvider,
		Iss:           "bap-controlplane",
		Aud:           "bap-edge-broker",
		Iat:           now.Unix(),
		Exp:           expiresAt.Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := headerB64 + "." + claimsB64
	mac := hmac.New(sha256.New, tm.signingKey)
	mac.Write([]byte(unsignedToken))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	jwtToken := unsignedToken + "." + sigB64
	return jwtToken, expiresAt, grantID, nil
}

// Verify verifies the cryptographic signature (BAP-408) and expiration of the token.
func (tm *TokenMinter) Verify(tokenStr string) (*GrantClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token structure")
	}

	unsignedToken := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, tm.signingKey)
	mac.Write([]byte(unsignedToken))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature (tampering detected)")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	var claims GrantClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims JSON: %w", err)
	}

	if time.Now().Unix() >= claims.Exp {
		return nil, fmt.Errorf("token has expired")
	}

	return &claims, nil
}

// Consume consumes a grant against a requested resource (backward-compatible).
func (tm *TokenMinter) Consume(tokenStr, resource string) (*GrantClaims, error) {
	return tm.ConsumeWithDetails(tokenStr, "", resource, "")
}

// ConsumeWithDetails validates grant integrity, matches against operation attributes (BAP-412),
// and atomically burns the grant according to stateful constraints (BAP-417).
func (tm *TokenMinter) ConsumeWithDetails(tokenStr, action, resource, sessionID string) (*GrantClaims, error) {
	claims, err := tm.Verify(tokenStr)
	if err != nil {
		return nil, err
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// 1. Stateful Grant Consumption (BAP-417)
	// Default max uses = 1 (single-use burned grant) unless explicitly configured otherwise
	maxUses := 1
	if claims.Constraints != nil && claims.Constraints.MaxUses > 0 {
		maxUses = claims.Constraints.MaxUses
	}

	usage := tm.consumedGrants[claims.GrantID]
	if usage != nil && usage.usesCount >= maxUses {
		return nil, fmt.Errorf("grant %s has exceeded maximum allowed uses (max: %d; replay blocked)", claims.GrantID, maxUses)
	}

	// 2. Session ID validation (BAP-403 & BAP-412)
	if claims.SessionID != "" && sessionID != "" {
		if !strings.EqualFold(claims.SessionID, sessionID) {
			return nil, fmt.Errorf("session mismatch: grant bound to session %q, but caller presented session %q", claims.SessionID, sessionID)
		}
	}

	// 3. Action validation (BAP-411 & BAP-412)
	if action != "" {
		if claims.Action != "" {
			if claims.Action != "*" && !strings.EqualFold(claims.Action, action) {
				return nil, fmt.Errorf("action mismatch: grant authorized action %q, attempted operation is %q", claims.Action, action)
			}
		} else {
			// Check against granted scopes
			matched := false
			for _, s := range claims.Scopes {
				if s == "*" || strings.EqualFold(s, action) || (strings.HasSuffix(s, "*") && strings.HasPrefix(action, strings.TrimSuffix(s, "*"))) {
					matched = true
					break
				}
				if (s == "api:read" && strings.HasSuffix(action, ".read")) || (s == "api:write" && (strings.HasSuffix(action, ".write") || strings.HasSuffix(action, ".update") || strings.HasSuffix(action, ".transfer"))) {
					matched = true
					break
				}
			}
			if !matched && len(claims.Scopes) > 0 {
				return nil, fmt.Errorf("grant scope does not authorize requested action %q", action)
			}
		}
	}

	// 4. Resource validation (BAP-412)
	if resource != "" {
		if claims.Resource != "" {
			if claims.Resource != "*" && !strings.EqualFold(claims.Resource, resource) && !strings.HasPrefix(resource, strings.TrimSuffix(claims.Resource, "*")) {
				return nil, fmt.Errorf("resource mismatch: grant authorized resource %q, requested resource is %q", claims.Resource, resource)
			}
		} else {
			// Check against granted scopes
			matched := false
			for _, s := range claims.Scopes {
				if s == "*" || strings.EqualFold(s, resource) {
					matched = true
					break
				}
				if strings.HasSuffix(s, "*") && strings.HasPrefix(resource, strings.TrimSuffix(s, "*")) {
					matched = true
					break
				}
				if (s == "api:read" || s == "api:write") && (strings.HasPrefix(resource, "/api/") || strings.EqualFold(s, resource)) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("grant scope does not authorize requested resource %q", resource)
			}
		}
	}

	// 5. Atomic state recording
	if usage == nil {
		tm.consumedGrants[claims.GrantID] = &grantUsage{
			consumedAt: time.Now(),
			usesCount:  1,
		}
	} else {
		usage.usesCount++
	}

	return claims, nil
}
