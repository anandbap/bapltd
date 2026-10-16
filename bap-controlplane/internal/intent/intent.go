package intent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrTaskNotFound    = errors.New("IntentAttestationError: task intent not found in registry")
	ErrTaskExpired     = errors.New("IntentAttestationError: task intent attestation has expired")
	ErrIntentDrift     = errors.New("TaskIntentDriftViolation: attempted operation diverges from attested task intent")
	ErrInvalidSignature = errors.New("IntentAttestationError: cryptographic intent signature mismatch")
)

// IntentAttestation represents an immutable, signed task context bound to an agent session
type IntentAttestation struct {
	TaskID            string    `json:"task_id"`
	SessionID         string    `json:"session_id"`
	RootOperatorEmail string    `json:"root_operator_email"`
	GoalDescription   string    `json:"goal_description"`
	IntentDigest      string    `json:"intent_digest"`
	PermittedEnvs     []string  `json:"permitted_envs"`
	PermittedActions  []string  `json:"permitted_actions"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Signature         string    `json:"signature"`
}

// IntentManager provides cryptographically signed intent bindings and anti-drift verification
type IntentManager struct {
	mu           sync.RWMutex
	signingKey   []byte
	attestations map[string]*IntentAttestation
}

// NewIntentManager creates an initialized IntentManager
func NewIntentManager(secret string) *IntentManager {
	if secret == "" {
		secret = "bap-default-intent-signing-secret"
	}
	return &IntentManager{
		signingKey:   []byte(secret),
		attestations: make(map[string]*IntentAttestation),
	}
}

// AttestIntent creates and cryptographically signs an immutable task intent binding
func (m *IntentManager) AttestIntent(taskID, sessionID, email, goal string, envs, actions []string, ttl time.Duration) (*IntentAttestation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.TrimSpace(taskID) == "" {
		return nil, errors.New("taskID is required for intent attestation")
	}
	if strings.TrimSpace(sessionID) == "" {
		return nil, errors.New("sessionID is required for intent attestation")
	}

	if ttl <= 0 {
		ttl = 30 * time.Minute
	}

	now := time.Now().UTC()
	digestRaw := fmt.Sprintf("%s|%s|%s|%s|%v|%v", taskID, sessionID, email, goal, envs, actions)
	digestHash := sha256.Sum256([]byte(digestRaw))
	intentDigest := hex.EncodeToString(digestHash[:])

	// Sign digest using HMAC-SHA256
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(intentDigest))
	sig := hex.EncodeToString(mac.Sum(nil))

	att := &IntentAttestation{
		TaskID:            taskID,
		SessionID:         sessionID,
		RootOperatorEmail: email,
		GoalDescription:   goal,
		IntentDigest:      intentDigest,
		PermittedEnvs:     envs,
		PermittedActions:  actions,
		IssuedAt:          now,
		ExpiresAt:         now.Add(ttl),
		Signature:         sig,
	}

	m.attestations[taskID] = att
	return att, nil
}

// VerifyActionAgainstIntent enforces that the attempted action does not diverge from the attested intent
func (m *IntentManager) VerifyActionAgainstIntent(taskID, attemptedAction, targetEnv string) (bool, string, error) {
	m.mu.RLock()
	att, exists := m.attestations[taskID]
	m.mu.RUnlock()

	if !exists {
		return false, "TaskNotFound", fmt.Errorf("%w: task %q", ErrTaskNotFound, taskID)
	}

	// 1. Expiration Check
	if time.Now().UTC().After(att.ExpiresAt) {
		return false, "TaskExpired", fmt.Errorf("%w: task %q expired at %s", ErrTaskExpired, taskID, att.ExpiresAt.Format(time.RFC3339))
	}

	// 2. Cryptographic Signature Verification
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(att.IntentDigest))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(att.Signature), []byte(expectedSig)) {
		return false, "SignatureMismatch", ErrInvalidSignature
	}

	// 3. Environment Scope Enforcement (e.g. Staging vs Production Invariant)
	if targetEnv != "" && len(att.PermittedEnvs) > 0 {
		envAllowed := false
		targetLower := strings.ToLower(targetEnv)
		for _, e := range att.PermittedEnvs {
			if e == "*" || strings.ToLower(e) == targetLower {
				envAllowed = true
				break
			}
		}
		if !envAllowed {
			reason := fmt.Sprintf("TaskIntentDriftViolation: attempted action targets environment %q but task is strictly bound to %v",
				targetEnv, att.PermittedEnvs)
			return false, "EnvironmentDrift", fmt.Errorf("%w: %s", ErrIntentDrift, reason)
		}
	}

	// 4. Destructive Action Enforcement (Railway Production Volume Deletion Prevention)
	actionLower := strings.ToLower(attemptedAction)
	isDestructive := strings.Contains(actionLower, "delete_volume") ||
		strings.Contains(actionLower, "drop_database") ||
		strings.Contains(actionLower, "drop_table") ||
		strings.Contains(actionLower, "destroy") ||
		strings.Contains(actionLower, "purge_backups")

	if isDestructive {
		destructiveAllowed := false
		for _, a := range att.PermittedActions {
			if a == "*" || strings.ToLower(a) == actionLower || strings.Contains(strings.ToLower(a), "destructive") {
				destructiveAllowed = true
				break
			}
		}
		if !destructiveAllowed {
			reason := fmt.Sprintf("TaskIntentDriftViolation: destructive operation %q blocked because task intent does not grant destructive authority",
				attemptedAction)
			return false, "DestructiveActionDrift", fmt.Errorf("%w: %s", ErrIntentDrift, reason)
		}
	}

	return true, "IntentVerified", nil
}

// GetAttestation retrieves an active task intent attestation
func (m *IntentManager) GetAttestation(taskID string) (*IntentAttestation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	att, exists := m.attestations[taskID]
	if !exists {
		return nil, ErrTaskNotFound
	}
	cp := *att
	return &cp, nil
}
