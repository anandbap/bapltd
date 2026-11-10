package authz

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

	"bap-edge/internal/identity"
	"bap-edge/pkg/types"
)

var (
	ErrZeroStandingPrivilegeViolation = errors.New("zero standing privileges violation: execution blocked without valid task grant")
	ErrGrantExpired                   = errors.New("task grant has expired")
	ErrGrantBurned                    = errors.New("task grant already burned (max uses exceeded)")
	ErrActionNotGranted               = errors.New("attempted action exceeds granted task scope")
	ErrResourceNotGranted             = errors.New("attempted resource target exceeds granted task boundaries")
	ErrInvalidEnvelope                = errors.New("invalid task authorization envelope")
)

// ZSPEngine implements Zero Standing Privileges and Just-In-Time Task Grant issuance (BAP-917).
type ZSPEngine struct {
	mu             sync.RWMutex
	minter         *identity.WorkstationIdentityMinter
	grants         map[string]*types.TaskGrant
	pepSecret      []byte
	lineageReceipts []types.AuditLineageProof
}

// NewZSPEngine creates a Zero Standing Privilege authorization engine.
func NewZSPEngine(minter *identity.WorkstationIdentityMinter, pepSecret string) *ZSPEngine {
	if pepSecret == "" {
		pepSecret = "bap-pep-local-authority-grant-signing-secret"
	}
	return &ZSPEngine{
		minter:         minter,
		grants:         make(map[string]*types.TaskGrant),
		pepSecret:      []byte(pepSecret),
		lineageReceipts: make([]types.AuditLineageProof, 0),
	}
}

// AuthorizeTaskEnvelope evaluates the 4-tuple task envelope and issues an attenuated task grant (BAP-916 & BAP-917).
func (e *ZSPEngine) AuthorizeTaskEnvelope(env *types.TaskAuthorizationEnvelope, maxUses int, ttl time.Duration) (*types.TaskGrant, error) {
	if env == nil {
		return nil, ErrInvalidEnvelope
	}

	// 1. Verify Agent SVID identity bound to human owner (BAP-915)
	if err := e.minter.VerifyAgentSVID(&env.Identity); err != nil {
		return nil, fmt.Errorf("agent identity verification failed: %w", err)
	}

	// 2. Verify Agent Cryptographic Signature on the 4-tuple envelope (BAP-916)
	if err := identity.VerifyEnvelopeSignature(env); err != nil {
		return nil, fmt.Errorf("envelope signature verification failed: %w", err)
	}

	// 3. Evaluate Non-Reliance & Cedar Invariants (BAP-914 & Zero Standing Privileges)
	plan := &types.PermissionPlan{
		RequestedActions:   env.PermissionAsk.Actions,
		RequestedResources: env.PermissionAsk.Resources,
	}
	if err := ValidateNonReliance(plan); err != nil {
		return nil, fmt.Errorf("envelope rejected by Cedar invariants: %w", err)
	}

	// 4. Apply Monotonic Scope Attenuation (BAP-902 & BAP-917)
	var allowedActions []string
	for _, act := range env.PermissionAsk.Actions {
		actLower := strings.ToLower(act)
		if strings.Contains(actLower, "admin:*") || strings.Contains(actLower, "repo:*") {
			// Attenuate wildcards
			allowedActions = append(allowedActions, "repo:read", "repo:push")
		} else {
			allowedActions = append(allowedActions, act)
		}
	}

	var allowedResources []string
	for _, res := range env.PermissionAsk.Resources {
		resLower := strings.ToLower(res)
		if resLower == "/*" || resLower == "repo://*" {
			allowedResources = append(allowedResources, "workspace://current")
		} else {
			allowedResources = append(allowedResources, res)
		}
	}

	if maxUses <= 0 {
		maxUses = 1 // Zero standing privileges: default single-use grant
	}
	if ttl <= 0 {
		ttl = 300 * time.Second // Ephemeral 5-minute bounded TTL
	}

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	grantID := fmt.Sprintf("grant-%s-%s", time.Now().Format("150405"), hex.EncodeToString(b))

	now := time.Now().UTC()
	grant := &types.TaskGrant{
		GrantID:          grantID,
		EnvelopeID:       env.EnvelopeID,
		SessionID:        env.Identity.SessionID,
		PrincipalSVID:    env.Identity.Subject,
		HumanOwner:       env.Identity.HumanOwner,
		AllowedActions:   allowedActions,
		AllowedResources: allowedResources,
		MaxUses:          maxUses,
		RemainingUses:    maxUses,
		IssuedAt:         now,
		ExpiresAt:        now.Add(ttl),
		IsBurned:         false,
	}

	// Sign the grant with PEP Authority Secret
	grant.AuthoritySignature = e.signGrant(grant)

	e.mu.Lock()
	e.grants[grantID] = grant
	e.mu.Unlock()

	return grant, nil
}

// ConsumeTaskGrant validates an execution request against an active grant and burns usage count (BAP-917 & BAP-918).
func (e *ZSPEngine) ConsumeTaskGrant(
	grantID string,
	attemptedAction string,
	targetResource string,
	commandExecuted string,
	processAncestry []string,
) (*types.AuditLineageProof, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if grantID == "" {
		return nil, ErrZeroStandingPrivilegeViolation
	}

	grant, exists := e.grants[grantID]
	if !exists {
		return nil, fmt.Errorf("%w: unrecognized grant ID %s", ErrZeroStandingPrivilegeViolation, grantID)
	}

	now := time.Now().UTC()
	if now.After(grant.ExpiresAt) {
		grant.IsBurned = true
		grant.BurnReason = "TTL Expired"
		return nil, ErrGrantExpired
	}

	if grant.IsBurned || grant.RemainingUses <= 0 {
		return nil, ErrGrantBurned
	}

	// Verify action is granted
	actionPermitted := false
	for _, allowed := range grant.AllowedActions {
		if strings.EqualFold(allowed, attemptedAction) || allowed == "*" || strings.HasPrefix(attemptedAction, allowed) {
			actionPermitted = true
			break
		}
	}
	if !actionPermitted {
		return nil, fmt.Errorf("%w: action %s not in granted scopes %v", ErrActionNotGranted, attemptedAction, grant.AllowedActions)
	}

	// Verify resource boundary is granted
	resourcePermitted := false
	for _, allowedRes := range grant.AllowedResources {
		if strings.EqualFold(allowedRes, targetResource) || allowedRes == "workspace://current" || strings.HasPrefix(targetResource, allowedRes) {
			resourcePermitted = true
			break
		}
	}
	if !resourcePermitted {
		return nil, fmt.Errorf("%w: resource %s not in granted boundaries %v", ErrResourceNotGranted, targetResource, grant.AllowedResources)
	}

	// Atomically burn one usage count
	grant.RemainingUses--
	if grant.RemainingUses == 0 {
		grant.IsBurned = true
		grant.BurnReason = "MaxUses Reached"
	}

	// Generate Non-Repudiation Audit Lineage Proof (BAP-918)
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	proofID := fmt.Sprintf("proof-%s-%s", now.Format("150405"), hex.EncodeToString(b))

	cmdHash := sha256.Sum256([]byte(commandExecuted))
	proof := types.AuditLineageProof{
		ProofID:            proofID,
		SessionID:          grant.SessionID,
		HumanOwner:         grant.HumanOwner,
		AgentPrincipalSVID: grant.PrincipalSVID,
		IntentMission:      grant.EnvelopeID,
		GrantID:            grant.GrantID,
		CommandExecuted:    commandExecuted,
		ExecutedBinaryHash: hex.EncodeToString(cmdHash[:]),
		ProcessAncestry:    processAncestry,
		DecisionResult:     "ALLOWED_EXECUTED",
		Timestamp:          now,
	}

	// Compute immutable cryptographic proof signature
	proof.LedgerSignature = e.signProof(&proof)
	e.lineageReceipts = append(e.lineageReceipts, proof)

	return &proof, nil
}

// GetGrant looks up an existing task grant.
func (e *ZSPEngine) GetGrant(grantID string) (*types.TaskGrant, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	g, ok := e.grants[grantID]
	if !ok {
		return nil, false
	}
	copy := *g
	return &copy, true
}

func (e *ZSPEngine) signGrant(g *types.TaskGrant) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%v|%v|%d|%d",
		g.GrantID, g.EnvelopeID, g.SessionID, g.PrincipalSVID,
		g.AllowedActions, g.AllowedResources, g.MaxUses, g.ExpiresAt.Unix())
	mac := hmac.New(sha256.New, e.pepSecret)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func (e *ZSPEngine) signProof(p *types.AuditLineageProof) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%d",
		p.ProofID, p.SessionID, p.HumanOwner, p.AgentPrincipalSVID,
		p.GrantID, p.CommandExecuted, p.ExecutedBinaryHash, p.Timestamp.Unix())
	mac := hmac.New(sha256.New, e.pepSecret)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}
