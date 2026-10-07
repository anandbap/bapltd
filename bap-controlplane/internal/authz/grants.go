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
	revokedGrants  map[string]string   // grantID -> reason
	grantChildren  map[string][]string // parentGrantID -> []childGrantID
	grantParent    map[string]string   // childGrantID -> parentGrantID
	grantRoot      map[string]string   // childGrantID -> rootGrantID
}

func NewTokenMinter(secretKey string, defaultTTL time.Duration) *TokenMinter {
	if defaultTTL <= 0 {
		defaultTTL = 30 * time.Minute
	}
	tm := &TokenMinter{
		signingKey:     []byte(secretKey),
		defaultTTL:     defaultTTL,
		consumedGrants: make(map[string]*grantUsage),
		revokedGrants:  make(map[string]string),
		grantChildren:  make(map[string][]string),
		grantParent:    make(map[string]string),
		grantRoot:      make(map[string]string),
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
	// Delegation Lineage & Attenuation (BAP-532)
	ParentGrantID   string                  `json:"parent_grant_id,omitempty"`
	ParentSessionID string                  `json:"parent_session_id,omitempty"`
	RootGrantID     string                  `json:"root_grant_id,omitempty"`
	RootAgentID     string                  `json:"root_agent_id,omitempty"`
	ParentAgentID string                  `json:"parent_agent_id,omitempty"`
	Lineage       []string                `json:"lineage,omitempty"`
	LineageTree   string                  `json:"lineage_tree,omitempty"`
	Caveats       []string                `json:"caveats,omitempty"`
	Depth         int                     `json:"depth,omitempty"`
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

	// Check if this grant or its parent/root has been revoked (BAP-532)
	if isRevoked, reason := tm.IsGrantRevoked(claims.GrantID); isRevoked {
		return nil, fmt.Errorf("grant %s is revoked: %s", claims.GrantID, reason)
	}
	if claims.ParentGrantID != "" {
		if isRevoked, reason := tm.IsGrantRevoked(claims.ParentGrantID); isRevoked {
			return nil, fmt.Errorf("parent grant %s is revoked: %s", claims.ParentGrantID, reason)
		}
	}
	if claims.RootGrantID != "" {
		if isRevoked, reason := tm.IsGrantRevoked(claims.RootGrantID); isRevoked {
			return nil, fmt.Errorf("root grant %s is revoked: %s", claims.RootGrantID, reason)
		}
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

// RevokeGrant atomically revokes a grant and all descendant child grants across the fleet (BAP-532).
func (tm *TokenMinter) RevokeGrant(grantID, reason string) []string {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	return tm.revokeGrantLocked(grantID, reason)
}

func (tm *TokenMinter) revokeGrantLocked(grantID, reason string) []string {
	if grantID == "" {
		return nil
	}
	var revoked []string
	if _, already := tm.revokedGrants[grantID]; !already {
		tm.revokedGrants[grantID] = reason
		revoked = append(revoked, grantID)
	}

	// Recursively revoke all children
	if children, exists := tm.grantChildren[grantID]; exists {
		for _, childID := range children {
			childRevoked := tm.revokeGrantLocked(childID, fmt.Sprintf("cascading revocation from parent grant %s: %s", grantID, reason))
			revoked = append(revoked, childRevoked...)
		}
	}
	return revoked
}

// IsGrantRevoked checks if a grant, or any ancestor in its delegation lineage, has been revoked.
func (tm *TokenMinter) IsGrantRevoked(grantID string) (bool, string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if reason, ok := tm.revokedGrants[grantID]; ok {
		return true, reason
	}
	if parentID, ok := tm.grantParent[grantID]; ok && parentID != "" {
		if reason, ok := tm.revokedGrants[parentID]; ok {
			return true, fmt.Sprintf("parent grant %s revoked: %s", parentID, reason)
		}
	}
	if rootID, ok := tm.grantRoot[grantID]; ok && rootID != "" {
		if reason, ok := tm.revokedGrants[rootID]; ok {
			return true, fmt.Sprintf("root grant %s revoked: %s", rootID, reason)
		}
	}
	return false, ""
}

// ListRevokedGrants returns all currently revoked grant IDs.
func (tm *TokenMinter) ListRevokedGrants() map[string]string {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	res := make(map[string]string, len(tm.revokedGrants))
	for k, v := range tm.revokedGrants {
		res[k] = v
	}
	return res
}

// VerifyAttenuation strictly verifies that child authority is a mathematical subset of parent authority (BAP-532).
// Monotonic attenuation rule: child scopes, resource, and action can only narrow or match parent, never broaden.
func VerifyAttenuation(parentScopes, childScopes []string, parentResource, childResource, parentAction, childAction string) error {
	// 1. Scopes Attenuation: every child scope MUST be permitted by parent scopes
	if len(parentScopes) > 0 {
		if len(childScopes) == 0 {
			return fmt.Errorf("PrivilegeEscalationBlocked: child subagent requested empty scopes while parent has bounded scopes")
		}
		for _, cs := range childScopes {
			allowed := false
			for _, ps := range parentScopes {
				if ps == "*" {
					allowed = true
					break
				}
				if ps == cs {
					allowed = true
					break
				}
				// Wildcard prefix matching: e.g. parent "fs:*" covers child "fs:read"
				if strings.HasSuffix(ps, "*") && strings.HasPrefix(cs, strings.TrimSuffix(ps, "*")) {
					allowed = true
					break
				}
				if ps == "admin:all" {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("PrivilegeEscalationBlocked: child subagent requested scope %q which is outside parent boundary %v", cs, parentScopes)
			}
		}
	}

	// 2. Resource Attenuation: child cannot broaden parent's resource
	if parentResource != "" && parentResource != "*" {
		if childResource == "" || childResource == "*" {
			return fmt.Errorf("PrivilegeEscalationBlocked: child subagent cannot broaden resource from %q to wildcard or empty", parentResource)
		}
		if strings.HasSuffix(parentResource, "/*") {
			base := strings.TrimSuffix(parentResource, "/*")
			if !strings.HasPrefix(childResource, base) {
				return fmt.Errorf("PrivilegeEscalationBlocked: child subagent resource %q violates parent boundary %q", childResource, parentResource)
			}
		} else if strings.HasSuffix(parentResource, "*") {
			base := strings.TrimSuffix(parentResource, "*")
			if !strings.HasPrefix(childResource, base) {
				return fmt.Errorf("PrivilegeEscalationBlocked: child subagent resource %q violates parent boundary %q", childResource, parentResource)
			}
		} else {
			if childResource != parentResource && !strings.HasPrefix(childResource, parentResource+"/") {
				return fmt.Errorf("PrivilegeEscalationBlocked: child subagent resource %q exceeds parent resource boundary %q", childResource, parentResource)
			}
		}
	}

	// 3. Action Attenuation: child cannot broaden parent's action
	if parentAction != "" && parentAction != "*" {
		if childAction == "" || childAction == "*" {
			return fmt.Errorf("PrivilegeEscalationBlocked: child subagent cannot broaden action from %q to wildcard", parentAction)
		}
		if !strings.EqualFold(parentAction, childAction) {
			return fmt.Errorf("PrivilegeEscalationBlocked: child subagent action %q exceeds parent action %q", childAction, parentAction)
		}
	}

	return nil
}

// DelegateAttenuatedChild mints an attenuated child grant (macaroon / caveat-chained JWT-SVID)
// cryptographically derived from a valid parent grant (BAP-532).
func (tm *TokenMinter) DelegateAttenuatedChild(
	parentToken string,
	childAgent *types.RegisteredAgent,
	requestedScopes []string,
	sessionID string,
	action string,
	resource string,
	constraints *types.GrantConstraints,
	ttlMins int,
) (string, time.Time, string, *GrantClaims, error) {
	parentClaims, err := tm.Verify(parentToken)
	if err != nil {
		return "", time.Time{}, "", nil, fmt.Errorf("invalid parent grant token: %w", err)
	}

	// Verify parent grant is not revoked
	if isRevoked, reason := tm.IsGrantRevoked(parentClaims.GrantID); isRevoked {
		return "", time.Time{}, "", nil, fmt.Errorf("parent grant %s is revoked: %s", parentClaims.GrantID, reason)
	}

	// Monotonic Attenuation check
	childScopes := requestedScopes
	if len(childScopes) == 0 {
		childScopes = parentClaims.Scopes
	}
	childResource := resource
	if childResource == "" {
		childResource = parentClaims.Resource
	}
	childAction := action
	if childAction == "" {
		childAction = parentClaims.Action
	}

	if err := VerifyAttenuation(parentClaims.Scopes, childScopes, parentClaims.Resource, childResource, parentClaims.Action, childAction); err != nil {
		return "", time.Time{}, "", nil, err
	}

	// Calculate expiration: child cannot exceed parent TTL
	now := time.Now().UTC()
	childTTL := tm.defaultTTL
	if ttlMins > 0 {
		childTTL = time.Duration(ttlMins) * time.Minute
	}
	expiresAt := now.Add(childTTL)
	parentExp := time.Unix(parentClaims.Exp, 0).UTC()
	if expiresAt.After(parentExp) {
		expiresAt = parentExp
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return "", time.Time{}, "", nil, fmt.Errorf("failed to generate random token id: %w", err)
	}
	childGrantID := fmt.Sprintf("grant-child-%x", idBytes)

	rootGrantID := parentClaims.RootGrantID
	if rootGrantID == "" {
		rootGrantID = parentClaims.GrantID
	}
	rootAgentID := parentClaims.RootAgentID
	if rootAgentID == "" {
		rootAgentID = parentClaims.Sub
	}

	lineage := make([]string, 0, len(parentClaims.Lineage)+2)
	if len(parentClaims.Lineage) == 0 {
		lineage = append(lineage, rootAgentID)
	} else {
		lineage = append(lineage, parentClaims.Lineage...)
	}
	childAgentID := childAgent.AgentID
	if childAgentID == "" {
		childAgentID = childAgent.AgentName
	}
	if childAgentID == "" {
		childAgentID = "subagent"
	}
	lineage = append(lineage, childAgentID)
	lineageTree := strings.Join(lineage, " -> ")

	// Macaroon caveat attenuation chaining
	caveats := make([]string, 0, len(parentClaims.Caveats)+2)
	caveats = append(caveats, parentClaims.Caveats...)
	caveat := fmt.Sprintf("attenuated:depth=%d;scopes=%s", parentClaims.Depth+1, strings.Join(childScopes, ","))
	caveats = append(caveats, caveat)

	sub := childAgent.AgentID
	if childAgent.SPIFFEID != "" {
		sub = childAgent.SPIFFEID
	}
	if sub == "" {
		sub = childAgentID
	}

	claims := GrantClaims{
		GrantID:       childGrantID,
		Sub:           sub,
		AppID:         childAgent.AppID,
		InstanceID:    childAgent.InstanceID,
		SPIFFEID:      childAgent.SPIFFEID,
		AgentName:     childAgent.AgentName,
		EnvProfile:    string(childAgent.EnvProfile),
		BinaryHash:    childAgent.EnrolledBinaryHash,
		SessionID:     sessionID,
		Action:        childAction,
		Resource:      childResource,
		Constraints:   constraints,
		PolicyVersion: parentClaims.PolicyVersion,
		Scopes:        childScopes,
		UserEmail:     parentClaims.UserEmail,
		Department:    parentClaims.Department,
		Groups:        parentClaims.Groups,
		AuthMode:      parentClaims.AuthMode,
		IdPProvider:   parentClaims.IdPProvider,
		ParentGrantID:   parentClaims.GrantID,
		ParentSessionID: parentClaims.SessionID,
		RootGrantID:     rootGrantID,
		RootAgentID:     rootAgentID,
		ParentAgentID:   parentClaims.Sub,
		Lineage:         lineage,
		LineageTree:     lineageTree,
		Caveats:         caveats,
		Depth:           parentClaims.Depth + 1,
		Iss:             "bap-controlplane",
		Aud:             "bap-edge-broker",
		Iat:           now.Unix(),
		Exp:           expiresAt.Unix(),
	}

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := headerB64 + "." + claimsB64
	mac := hmac.New(sha256.New, tm.signingKey)
	mac.Write([]byte(unsignedToken))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	jwtToken := unsignedToken + "." + sigB64

	// Track hierarchy in minter
	tm.mu.Lock()
	tm.grantChildren[parentClaims.GrantID] = append(tm.grantChildren[parentClaims.GrantID], childGrantID)
	tm.grantParent[childGrantID] = parentClaims.GrantID
	tm.grantRoot[childGrantID] = rootGrantID
	tm.mu.Unlock()

	return jwtToken, expiresAt, childGrantID, &claims, nil
}

