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
	ErrHighRiskApprovalRequired       = errors.New("high-risk privilege escalation requires out-of-band interactive human approval")
)

// IsHighRiskEscalationAction returns true for privilege-escalation, policy-mutation,
// or governance-override actions that an autonomous agent may never self-mint.
func IsHighRiskEscalationAction(action string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	if a == "" {
		return false
	}
	highRiskPrefixes := []string{
		"policy:",
		"grant:",
		"admin:",
		"iam:",
		"bap:override",
		"bap:dev-override",
		"dev-override:",
		"security:override",
		"sudo:",
	}
	for _, p := range highRiskPrefixes {
		if strings.HasPrefix(a, p) || a == strings.TrimSuffix(p, ":") {
			return true
		}
	}
	return a == "system:admin" || strings.HasSuffix(a, ":elevate") || strings.HasSuffix(a, ":override")
}

// FindHighRiskEscalationActions returns the subset of requested actions that require out-of-band HITL approval.
func FindHighRiskEscalationActions(actions []string) []string {
	var hits []string
	for _, act := range actions {
		if IsHighRiskEscalationAction(act) {
			hits = append(hits, act)
		}
	}
	return hits
}

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

	// 3b. Enforce Out-of-Band Interactive Human Approval for High-Risk Escalation Actions
	if highRisk := FindHighRiskEscalationActions(env.PermissionAsk.Actions); len(highRisk) > 0 {
		if env.AuthorizedBy.DelegationType != "human_interactive_oob" {
			return nil, fmt.Errorf("%w: action(s) %v cannot be autonomously minted by an agent", ErrHighRiskApprovalRequired, highRisk)
		}
	}

	// 4. Apply Monotonic Scope Attenuation (BAP-902 & BAP-917)
	var allowedActions []string
	narrowed := false
	for _, act := range env.PermissionAsk.Actions {
		actLower := strings.ToLower(act)
		if strings.Contains(actLower, "admin:*") || strings.Contains(actLower, "repo:*") {
			// Attenuate wildcards
			allowedActions = append(allowedActions, "repo:read", "repo:push")
			narrowed = true
		} else {
			allowedActions = append(allowedActions, act)
		}
	}

	var allowedResources []string
	for _, res := range env.PermissionAsk.Resources {
		resLower := strings.ToLower(res)
		if resLower == "/*" || resLower == "repo://*" {
			allowedResources = append(allowedResources, "workspace://current")
			narrowed = true
		} else {
			allowedResources = append(allowedResources, res)
		}
	}

	narrowingReason := ""
	if narrowed {
		narrowingReason = fmt.Sprintf("Monotonic scope attenuation: requested %v on %v narrowed to %v on %v",
			env.PermissionAsk.Actions, env.PermissionAsk.Resources, allowedActions, allowedResources)
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
		GrantID:            grantID,
		EnvelopeID:         env.EnvelopeID,
		SessionID:          env.Identity.SessionID,
		PrincipalSVID:      env.Identity.Subject,
		HumanOwner:         env.Identity.HumanOwner,
		AllowedActions:     allowedActions,
		AllowedResources:   allowedResources,
		RequestedActions:   append([]string(nil), env.PermissionAsk.Actions...),
		RequestedResources: append([]string(nil), env.PermissionAsk.Resources...),
		NarrowingApplied:   narrowed,
		NarrowingReason:    narrowingReason,
		MaxUses:            maxUses,
		RemainingUses:      maxUses,
		IssuedAt:           now,
		ExpiresAt:          now.Add(ttl),
		IsBurned:           false,
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
		if actionMatchesGrant(allowed, attemptedAction) {
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
		if resourceMatchesGrant(allowedRes, targetResource) {
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

// LoadGrant verifies a persisted TaskGrant's PEP HMAC signature and registers it in memory.
func (e *ZSPEngine) LoadGrant(g *types.TaskGrant) error {
	if g == nil || g.GrantID == "" {
		return ErrZeroStandingPrivilegeViolation
	}
	expected := e.signGrant(g)
	if !hmac.Equal([]byte(expected), []byte(g.AuthoritySignature)) {
		return fmt.Errorf("%w: forged or tampered task grant %s", ErrZeroStandingPrivilegeViolation, g.GrantID)
	}
	e.mu.Lock()
	copy := *g
	e.grants[g.GrantID] = &copy
	e.mu.Unlock()
	return nil
}

// CheckTaskGrant verifies an active grant matches action and resource without decrementing uses.
func (e *ZSPEngine) CheckTaskGrant(grantID, attemptedAction, targetResource string) (*types.TaskGrant, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if grantID == "" {
		return nil, ErrZeroStandingPrivilegeViolation
	}
	grant, exists := e.grants[grantID]
	if !exists {
		return nil, fmt.Errorf("%w: unrecognized grant ID %s", ErrZeroStandingPrivilegeViolation, grantID)
	}
	now := time.Now().UTC()
	if now.After(grant.ExpiresAt) {
		return nil, ErrGrantExpired
	}
	if grant.IsBurned || grant.RemainingUses <= 0 {
		return nil, ErrGrantBurned
	}
	actionPermitted := false
	for _, allowed := range grant.AllowedActions {
		if actionMatchesGrant(allowed, attemptedAction) {
			actionPermitted = true
			break
		}
	}
	if !actionPermitted {
		return nil, fmt.Errorf("%w: action %s not in granted scopes %v", ErrActionNotGranted, attemptedAction, grant.AllowedActions)
	}
	resourcePermitted := false
	for _, allowedRes := range grant.AllowedResources {
		if resourceMatchesGrant(allowedRes, targetResource) {
			resourcePermitted = true
			break
		}
	}
	if !resourcePermitted {
		return nil, fmt.Errorf("%w: resource %s not in granted boundaries %v", ErrResourceNotGranted, targetResource, grant.AllowedResources)
	}
	copy := *grant
	return &copy, nil
}

// MarkGrantBurned revokes or burns an active grant in memory.
func (e *ZSPEngine) MarkGrantBurned(grantID, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	g, ok := e.grants[grantID]
	if !ok {
		return ErrZeroStandingPrivilegeViolation
	}
	g.IsBurned = true
	g.RemainingUses = 0
	g.BurnReason = reason
	return nil
}

func actionMatchesGrant(allowed, attempted string) bool {
	a := strings.ToLower(strings.TrimSpace(allowed))
	t := strings.ToLower(strings.TrimSpace(attempted))
	if a == "" || t == "" {
		return false
	}
	if a == "*" || a == t {
		return true
	}
	if strings.HasSuffix(a, ":*") && strings.HasPrefix(t, strings.TrimSuffix(a, "*")) {
		return true
	}
	if strings.HasPrefix(t, a+":") || strings.HasPrefix(t, a) {
		return true
	}
	if a == "repo:read" || a == "fs:read" || a == "git:inspect:read" || a == "git:read" {
		if t == "git:status" || t == "git:log" || t == "git:diff" || t == "git:show" || t == "git:branch" ||
			t == "git:inspect:read" ||
			strings.HasPrefix(t, "git:status") || strings.HasPrefix(t, "git:log") || strings.HasPrefix(t, "git:diff") {
			return true
		}
		if a == "repo:read" || a == "fs:read" {
			if strings.HasPrefix(t, "fs:file:read") || strings.HasPrefix(t, "fs:dir:read") {
				return true
			}
		}
	}
	if a == "repo:write" || a == "fs:write" {
		if strings.HasPrefix(t, "fs:file:write") || strings.HasPrefix(t, "fs:file:edit") {
			return true
		}
	}
	return false
}

func resourceMatchesGrant(allowedRes, targetResource string) bool {
	a := strings.ToLower(strings.TrimSpace(allowedRes))
	t := strings.ToLower(strings.TrimSpace(targetResource))
	if a == "" || t == "" {
		return false
	}
	if a == t {
		return true
	}
	if a == "workspace://current" || a == "workspace://." {
		if t == "workspace://current" || t == "workspace://." || t == "repo:local" ||
			strings.HasPrefix(t, "workspace://") || strings.HasPrefix(t, "repo:") {
			return true
		}
		return false
	}
	return strings.HasPrefix(t, a)
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
