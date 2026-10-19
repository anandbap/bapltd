package tokenexchange

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrGrantAlreadyBurned    = errors.New("GrantAlreadyBurned: single-use grant token has already been consumed")
	ErrGrantExpired          = errors.New("GrantExpired: grant token has expired")
	ErrUnapprovedService     = errors.New("UnapprovedService: destination service not permitted for JIT credential brokering")
	ErrInvalidGrantType      = errors.New("unsupported_grant_type: grant_type must be urn:ietf:params:oauth:grant-type:token-exchange")
	ErrInvalidSubjectToken   = errors.New("invalid_grant: subject_token is missing or invalid")
	ErrScopeEscalationDenied = errors.New("invalid_scope: requested scope exceeds authorized boundary (privilege escalation blocked)")
)

const (
	RFC8693GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	RFC8693TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	RFC8693TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
)

// ExchangedCredential represents an ephemeral, short-lived credential brokered for a downstream service
type ExchangedCredential struct {
	Service            string    `json:"service"`             // e.g. "railway", "aws", "github", "salesforce"
	TargetEnv          string    `json:"target_env"`          // e.g. "staging", "dev"
	EphemeralToken     string    `json:"ephemeral_token"`     // short-lived 5-minute downstream token
	BoundTaskID        string    `json:"bound_task_id"`
	BoundSessionID     string    `json:"bound_session_id"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	BurnedGrantTokenID string    `json:"burned_grant_token_id"`
}

// RFC8693TokenExchangeRequest represents an RFC 8693 Token Exchange request (BAP-702).
type RFC8693TokenExchangeRequest struct {
	GrantType          string `json:"grant_type"`
	Resource           string `json:"resource,omitempty"`
	Audience           string `json:"audience,omitempty"`
	Scope              string `json:"scope,omitempty"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	ActorToken         string `json:"actor_token,omitempty"`
	ActorTokenType     string `json:"actor_token_type,omitempty"`
	SessionID          string `json:"session_id,omitempty"`
	TaskID             string `json:"task_id,omitempty"`
	AuthorizedScopes   string `json:"authorized_scopes,omitempty"`
}

// RFC8693TokenExchangeResponse represents the standard RFC 8693 Token Exchange response.
type RFC8693TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"` // "Bearer"
	ExpiresIn       int    `json:"expires_in"` // seconds (e.g. 300)
	Scope           string `json:"scope,omitempty"`
}

// TokenExchangeGateway governs single-use grant burning and downstream JIT credential translation
type TokenExchangeGateway struct {
	mu             sync.Mutex
	consumedGrants map[string]time.Time // grantToken -> burnedAt
	signingSecret  []byte
}

// NewTokenExchangeGateway initializes the JIT token exchange gateway
func NewTokenExchangeGateway(secret string) *TokenExchangeGateway {
	if secret == "" {
		secret = "bap-default-exchange-gateway-secret"
	}
	return &TokenExchangeGateway{
		consumedGrants: make(map[string]time.Time),
		signingSecret:  []byte(secret),
	}
}

// BurnGrantOnce atomically consumes a single-use grant token, rejecting replay attacks
func (g *TokenExchangeGateway) BurnGrantOnce(grantToken string) (bool, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	trimmed := strings.TrimSpace(grantToken)
	if trimmed == "" {
		return false, "MissingGrantToken", errors.New("grantToken is required")
	}

	if burnedAt, exists := g.consumedGrants[trimmed]; exists {
		reason := fmt.Sprintf("GrantAlreadyBurned: single-use grant token was already consumed at %s", burnedAt.Format(time.RFC3339))
		return false, "GrantAlreadyBurned", fmt.Errorf("%w: %s", ErrGrantAlreadyBurned, reason)
	}

	now := time.Now().UTC()
	g.consumedGrants[trimmed] = now
	return true, "GrantBurnedSuccessfully", nil
}

// BrokerDownstreamCredential mints an ephemeral, short-lived downstream credential
func (g *TokenExchangeGateway) BrokerDownstreamCredential(service, targetEnv, taskID, sessionID, grantToken string) (*ExchangedCredential, error) {
	// First burn the grant token
	burned, status, err := g.BurnGrantOnce(grantToken)
	if !burned || err != nil {
		return nil, fmt.Errorf("credential brokering denied: %s (%w)", status, err)
	}

	serviceLower := strings.ToLower(service)
	envLower := strings.ToLower(targetEnv)

	// Validate service
	if serviceLower != "railway" && serviceLower != "aws" && serviceLower != "github" && serviceLower != "salesforce" && serviceLower != "stripe" {
		return nil, fmt.Errorf("%w: %q", ErrUnapprovedService, service)
	}

	// Generate short-lived ephemeral credential (5 minute TTL)
	now := time.Now().UTC()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	rawToken := fmt.Sprintf("jit-%s-%s-%s", serviceLower, envLower, hex.EncodeToString(b))

	mac := hmac.New(sha256.New, g.signingSecret)
	mac.Write([]byte(rawToken))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]

	ephemeralToken := fmt.Sprintf("%s.%s", rawToken, sig)

	cred := &ExchangedCredential{
		Service:            serviceLower,
		TargetEnv:          envLower,
		EphemeralToken:     ephemeralToken,
		BoundTaskID:        taskID,
		BoundSessionID:     sessionID,
		IssuedAt:           now,
		ExpiresAt:          now.Add(5 * time.Minute),
		BurnedGrantTokenID: grantToken,
	}

	return cred, nil
}

// ExchangeRFC8693Token performs RFC 8693 token exchange with single-use burning and anti-escalation enforcement.
func (g *TokenExchangeGateway) ExchangeRFC8693Token(req RFC8693TokenExchangeRequest) (*RFC8693TokenExchangeResponse, error) {
	if req.GrantType != RFC8693GrantTypeTokenExchange {
		return nil, fmt.Errorf("%w: received %s", ErrInvalidGrantType, req.GrantType)
	}

	trimmedSubject := strings.TrimSpace(req.SubjectToken)
	if trimmedSubject == "" {
		return nil, ErrInvalidSubjectToken
	}

	// Scope verification: requested scope cannot exceed authorized scopes (no privilege amplification)
	if req.Scope != "" && req.AuthorizedScopes != "" {
		reqScopes := strings.Fields(req.Scope)
		authScopes := strings.Fields(req.AuthorizedScopes)
		authMap := make(map[string]bool)
		for _, s := range authScopes {
			authMap[s] = true
		}
		for _, s := range reqScopes {
			if !authMap[s] {
				return nil, fmt.Errorf("%w: requested %q not in authorized list", ErrScopeEscalationDenied, s)
			}
		}
	}

	// Atomically burn single-use subject grant token
	burned, status, err := g.BurnGrantOnce(trimmedSubject)
	if !burned || err != nil {
		return nil, fmt.Errorf("token exchange rejected: %s (%w)", status, err)
	}

	// Mint scoped ephemeral token
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	rawToken := fmt.Sprintf("bap-exchanged-%s", hex.EncodeToString(b))

	mac := hmac.New(sha256.New, g.signingSecret)
	mac.Write([]byte(rawToken))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]
	accessToken := fmt.Sprintf("%s.%s", rawToken, sig)

	scope := req.Scope
	if scope == "" {
		scope = req.AuthorizedScopes
	}
	if scope == "" {
		scope = "read"
	}

	issuedType := req.RequestedTokenType
	if issuedType == "" {
		issuedType = RFC8693TokenTypeAccessToken
	}

	return &RFC8693TokenExchangeResponse{
		AccessToken:     accessToken,
		IssuedTokenType: issuedType,
		TokenType:       "Bearer",
		ExpiresIn:       300, // 5-minute bounded TTL
		Scope:           scope,
	}, nil
}
