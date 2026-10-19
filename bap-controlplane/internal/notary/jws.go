package notary

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidJWSToken     = errors.New("InvalidJWSToken: malformed or corrupted JWS compact serialization")
	ErrJWSSignatureMismatch = errors.New("JWSSignatureMismatch: signature verification failed")
	ErrJWSTokenExpired     = errors.New("JWSTokenExpired: assertion token timestamp has expired")
	ErrJWSTokenPremature   = errors.New("JWSTokenPremature: assertion token used prior to nbf")
	ErrJWSUntrustedIssuer  = errors.New("JWSUntrustedIssuer: token issuer not recognized in trust store")
	ErrJWSInvalidAudience  = errors.New("JWSInvalidAudience: token audience mismatch")
)

// JWSHeader conforms to RFC 7515 Section 4.
type JWSHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// JWSClaims represents the standard and BAP-specific claims in a signed assertion.
type JWSClaims struct {
	Iss           string   `json:"iss"`
	Sub           string   `json:"sub"`
	Aud           string   `json:"aud"`
	Exp           int64    `json:"exp"`
	Nbf           int64    `json:"nbf"`
	Iat           int64    `json:"iat"`
	Jti           string   `json:"jti"`
	SessionID     string   `json:"bap_session_id,omitempty"`
	TaskID        string   `json:"bap_task_id,omitempty"`
	AgentID       string   `json:"bap_agent_id,omitempty"`
	Intent        string   `json:"bap_intent,omitempty"`
	RiskTier      string   `json:"bap_risk_tier,omitempty"`
	Scopes        []string `json:"scp,omitempty"`
	DelegationURI string   `json:"bap_delegation,omitempty"`
}

// JWKKey represents an RFC 7517 JSON Web Key for public distribution.
type JWKKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	K   string `json:"k,omitempty"` // For symmetric/test or thumbprint
}

// JWKSResponse represents the RFC 7517 JSON Web Key Set.
type JWKSResponse struct {
	Keys []JWKKey `json:"keys"`
}

// JWSTrustStore manages active and rotated signing keys and verifies incoming JWS assertions.
type JWSTrustStore struct {
	mu           sync.RWMutex
	currentKid   string
	keys         map[string][]byte // kid -> key secret
	issuer       string
	expectedAud  string
	maxClockSkew time.Duration
}

// NewJWSTrustStore initializes the JWS manager and trust store.
func NewJWSTrustStore(issuer, defaultAudience, initialSecret string) *JWSTrustStore {
	if issuer == "" {
		issuer = "https://controlplane.bap.internal"
	}
	if defaultAudience == "" {
		defaultAudience = "https://gateway.bap.internal"
	}
	if initialSecret == "" {
		initialSecret = "bap-default-jws-enterprise-signing-secret"
	}

	kid := "bap-key-2026-v1"
	store := &JWSTrustStore{
		currentKid:   kid,
		keys:         make(map[string][]byte),
		issuer:       issuer,
		expectedAud:  defaultAudience,
		maxClockSkew: 30 * time.Second,
	}
	store.keys[kid] = []byte(initialSecret)
	return store
}

// RotateKey generates or registers a new signing key ID, maintaining older keys for the transition period.
func (s *JWSTrustStore) RotateKey(newKid, newSecret string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if newKid == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		newKid = fmt.Sprintf("bap-key-%s", hex.EncodeToString(b))
	}
	s.keys[newKid] = []byte(newSecret)
	s.currentKid = newKid
}

// SignClaims creates an RFC 7515 compliant compact JWS token (header.payload.signature).
func (s *JWSTrustStore) SignClaims(claims JWSClaims) (string, error) {
	s.mu.RLock()
	kid := s.currentKid
	secret := s.keys[kid]
	s.mu.RUnlock()

	if claims.Iss == "" {
		claims.Iss = s.issuer
	}
	if claims.Aud == "" {
		claims.Aud = s.expectedAud
	}
	now := time.Now().UTC()
	if claims.Iat == 0 {
		claims.Iat = now.Unix()
	}
	if claims.Nbf == 0 {
		claims.Nbf = now.Unix()
	}
	if claims.Exp == 0 {
		claims.Exp = now.Add(5 * time.Minute).Unix() // 5-minute bounded TTL per BAP-701/ZSP
	}
	if claims.Jti == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		claims.Jti = fmt.Sprintf("jti-%s", hex.EncodeToString(b))
	}

	header := JWSHeader{
		Alg: "HS256",
		Typ: "JWT",
		Kid: kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := encHeader + "." + encPayload

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(signingInput))
	sig := h.Sum(nil)
	encSig := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + encSig, nil
}

// VerifyToken verifies the compact JWS token's signature, issuer, audience, and temporal validity.
func (s *JWSTrustStore) VerifyToken(tokenString string, expectedAudience string) (*JWSClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWSToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid header encoding", ErrInvalidJWSToken)
	}

	var header JWSHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: invalid header JSON", ErrInvalidJWSToken)
	}

	s.mu.RLock()
	secret, exists := s.keys[header.Kid]
	s.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("unknown key ID (kid: %s): not present in trust store", header.Kid)
	}

	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(signingInput))
	expectedSig := h.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding", ErrInvalidJWSToken)
	}

	if !hmac.Equal(actualSig, expectedSig) {
		return nil, ErrJWSSignatureMismatch
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload encoding", ErrInvalidJWSToken)
	}

	var claims JWSClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: invalid payload JSON", ErrInvalidJWSToken)
	}

	// Verify Issuer
	if claims.Iss != s.issuer {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrJWSUntrustedIssuer, s.issuer, claims.Iss)
	}

	// Verify Audience
	targetAud := expectedAudience
	if targetAud == "" {
		targetAud = s.expectedAud
	}
	if claims.Aud != targetAud {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrJWSInvalidAudience, targetAud, claims.Aud)
	}

	// Verify Time Bounds with skew allowance
	nowUnix := time.Now().UTC().Unix()
	skew := int64(s.maxClockSkew.Seconds())
	if claims.Exp != 0 && (nowUnix > claims.Exp+skew) {
		return nil, ErrJWSTokenExpired
	}
	if claims.Nbf != 0 && (nowUnix < claims.Nbf-skew) {
		return nil, ErrJWSTokenPremature
	}

	return &claims, nil
}

// GetJWKS returns public key definitions for RFC 7517 endpoint consumption.
func (s *JWSTrustStore) GetJWKS() JWKSResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []JWKKey
	for kid := range s.keys {
		keys = append(keys, JWKKey{
			Kty: "oct",
			Use: "sig",
			Kid: kid,
			Alg: "HS256",
		})
	}
	return JWKSResponse{Keys: keys}
}
