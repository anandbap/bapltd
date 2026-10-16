package hitl

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
	ErrDuplicateRequestThrottled = errors.New("ApprovalFatigueThrottled: duplicate escalation suppressed to prevent reviewer fatigue")
	ErrMaxAttemptsExceeded       = errors.New("MaxEscalationAttemptsExceeded: task has exceeded maximum allowed escalation attempts")
	ErrEscalationNotFound        = errors.New("EscalationNotFound: escalation request not found")
	ErrEscalationAlreadyResolved = errors.New("EscalationAlreadyResolved: escalation request has already been decided")
)

type RiskRating string

const (
	RiskLow      RiskRating = "LOW"
	RiskMedium   RiskRating = "MEDIUM"
	RiskHigh     RiskRating = "HIGH"
	RiskCritical RiskRating = "CRITICAL"
)

type EscalationStatus string

const (
	StatusPending   EscalationStatus = "PENDING"
	StatusApproved  EscalationStatus = "APPROVED"
	StatusDenied    EscalationStatus = "DENIED"
	StatusThrottled EscalationStatus = "THROTTLED"
)

// EscalationRequest encapsulates the complete task context for a human reviewer
type EscalationRequest struct {
	EscalationID   string           `json:"escalation_id"`
	TaskID         string           `json:"task_id"`
	SessionID      string           `json:"session_id"`
	AgentID        string           `json:"agent_id"`
	Resource       string           `json:"resource"`
	Action         string           `json:"action"`
	Reason         string           `json:"reason"`
	RiskRating     RiskRating       `json:"risk_rating"`
	RequestedAt    time.Time        `json:"requested_at"`
	ResolvedAt     *time.Time       `json:"resolved_at,omitempty"`
	ReviewerEmail  string           `json:"reviewer_email,omitempty"`
	Status         EscalationStatus `json:"status"`
	EphemeralGrant string           `json:"ephemeral_grant,omitempty"`
	ExpiresAt      *time.Time       `json:"expires_at,omitempty"`
}

// EscalationManager governs contextual task step-up escalation and approval fatigue throttling
type EscalationManager struct {
	mu                 sync.Mutex
	signingSecret      []byte
	cooldownDuration   time.Duration
	maxAttemptsPerTask int
	requests           map[string]*EscalationRequest
	recentAttempts     map[string]time.Time // key (taskID:resource:action) -> lastRequestedAt
	taskAttemptCounts  map[string]int       // taskID -> total escalation requests
}

// NewEscalationManager initializes the HITL escalation subsystem
func NewEscalationManager(secret string, cooldown time.Duration, maxAttempts int) *EscalationManager {
	if secret == "" {
		secret = "bap-default-hitl-escalation-secret"
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	return &EscalationManager{
		signingSecret:      []byte(secret),
		cooldownDuration:   cooldown,
		maxAttemptsPerTask: maxAttempts,
		requests:           make(map[string]*EscalationRequest),
		recentAttempts:     make(map[string]time.Time),
		taskAttemptCounts:  make(map[string]int),
	}
}

// computeDeduplicationKey creates a unique key per task, resource, and action
func computeDeduplicationKey(taskID, resource, action string) string {
	return fmt.Sprintf("%s|%s|%s", strings.TrimSpace(taskID), strings.TrimSpace(resource), strings.TrimSpace(action))
}

// AssessRisk calculates a risk rating based on requested action and resource
func AssessRisk(resource, action string) RiskRating {
	resLower := strings.ToLower(resource)
	actLower := strings.ToLower(action)

	if strings.Contains(actLower, "drop") || strings.Contains(actLower, "delete") || strings.Contains(resLower, "production") || strings.Contains(resLower, "prod") {
		return RiskCritical
	}
	if strings.Contains(actLower, "write") || strings.Contains(actLower, "modify") || strings.Contains(actLower, "upload") || strings.Contains(resLower, "s3://") {
		return RiskHigh
	}
	if strings.Contains(actLower, "deploy") || strings.Contains(actLower, "restart") {
		return RiskMedium
	}
	return RiskLow
}

// RequestEscalation submits a new out-of-scope escalation request with approval fatigue suppression
func (em *EscalationManager) RequestEscalation(taskID, sessionID, agentID, resource, action, reason string) (*EscalationRequest, error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	now := time.Now().UTC()
	dedupKey := computeDeduplicationKey(taskID, resource, action)

	// 1. Fatigue Prevention: Check duplicate request within cooldown window
	if lastReq, exists := em.recentAttempts[dedupKey]; exists {
		if now.Sub(lastReq) < em.cooldownDuration {
			remaining := em.cooldownDuration - now.Sub(lastReq)
			return nil, fmt.Errorf("%w: duplicate request within cooldown window (retry allowed in %v)", ErrDuplicateRequestThrottled, remaining.Round(time.Second))
		}
	}

	// 2. Max attempts check
	attempts := em.taskAttemptCounts[taskID]
	if attempts >= em.maxAttemptsPerTask {
		return nil, fmt.Errorf("%w: task %s reached maximum allowed %d escalations", ErrMaxAttemptsExceeded, taskID, em.maxAttemptsPerTask)
	}

	// 3. Generate unique Escalation ID
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	escID := fmt.Sprintf("esc-%x", b)

	risk := AssessRisk(resource, action)

	req := &EscalationRequest{
		EscalationID: escID,
		TaskID:       taskID,
		SessionID:    sessionID,
		AgentID:      agentID,
		Resource:     resource,
		Action:       action,
		Reason:       reason,
		RiskRating:   risk,
		RequestedAt:  now,
		Status:       StatusPending,
	}

	em.requests[escID] = req
	em.recentAttempts[dedupKey] = now
	em.taskAttemptCounts[taskID] = attempts + 1

	return req, nil
}

// ResolveEscalation applies a human reviewer's decision to an active escalation request
func (em *EscalationManager) ResolveEscalation(escalationID, decision, reviewerEmail string, ttlDuration time.Duration) (*EscalationRequest, error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	req, exists := em.requests[escalationID]
	if !exists {
		return nil, ErrEscalationNotFound
	}

	if req.Status != StatusPending {
		return nil, fmt.Errorf("%w: request is currently %s", ErrEscalationAlreadyResolved, req.Status)
	}

	now := time.Now().UTC()
	req.ResolvedAt = &now
	req.ReviewerEmail = reviewerEmail

	decisionLower := strings.ToLower(strings.TrimSpace(decision))
	if decisionLower == "approve" || decisionLower == "approved" || decisionLower == "allow" {
		req.Status = StatusApproved

		// Mint short-lived, task-scoped ephemeral grant
		if ttlDuration <= 0 {
			ttlDuration = 5 * time.Minute
		}
		exp := now.Add(ttlDuration)
		req.ExpiresAt = &exp

		// Cryptographic HMAC-signed single-task token
		rawGrant := fmt.Sprintf("task-grant-%s-%s-%s-%d", req.TaskID, req.Action, escalationID, exp.Unix())
		mac := hmac.New(sha256.New, em.signingSecret)
		mac.Write([]byte(rawGrant))
		sig := hex.EncodeToString(mac.Sum(nil))[:16]

		req.EphemeralGrant = fmt.Sprintf("%s.%s", rawGrant, sig)
	} else {
		req.Status = StatusDenied
	}

	return req, nil
}

// GetEscalation queries an escalation request by ID
func (em *EscalationManager) GetEscalation(escalationID string) (*EscalationRequest, error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	req, exists := em.requests[escalationID]
	if !exists {
		return nil, ErrEscalationNotFound
	}
	return req, nil
}

// ListEscalations returns all escalation requests
func (em *EscalationManager) ListEscalations() []*EscalationRequest {
	em.mu.Lock()
	defer em.mu.Unlock()

	res := make([]*EscalationRequest, 0, len(em.requests))
	for _, r := range em.requests {
		res = append(res, r)
	}
	return res
}
