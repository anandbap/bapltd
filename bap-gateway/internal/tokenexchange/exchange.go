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
	ErrGrantAlreadyBurned = errors.New("GrantAlreadyBurned: single-use grant token has already been consumed")
	ErrGrantExpired       = errors.New("GrantExpired: grant token has expired")
	ErrUnapprovedService  = errors.New("UnapprovedService: destination service not permitted for JIT credential brokering")
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

// TokenExchangeGateway governs single-use grant burning and downstream JIT credential translation
type TokenExchangeGateway struct {
	mu           sync.Mutex
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
