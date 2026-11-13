package types

import (
	"strings"
	"time"
)

type EnvProfile string

const (
	ProfileDev  EnvProfile = "development"
	ProfileProd EnvProfile = "production"
)

type AgentStatus string

const (
	StatusPendingEnrollment AgentStatus = "pending_enrollment"
	StatusActive            AgentStatus = "active"
	StatusRevoked           AgentStatus = "revoked"
	StatusOffline           AgentStatus = "offline"
	StatusQuarantined       AgentStatus = "quarantined"
	StatusDeregistered      AgentStatus = "deregistered"
)

// SanitizeInstanceID normalizes hostnames and labels into safe identifiers.
func SanitizeInstanceID(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	res := strings.Trim(sb.String(), "-")
	if res == "" {
		return "workstation"
	}
	return res
}

type RegisteredAgent struct {
	SupersededBy        string      `json:"superseded_by,omitempty"`
	RecoveryOnly        bool        `json:"recovery_only,omitempty"`
	AgentID             string      `json:"agent_id"`
	AppID               string      `json:"app_id"`
	InstanceID          string      `json:"instance_id,omitempty"`
	SPIFFEID            string      `json:"spiffe_id,omitempty"`
	TrustDomain         string      `json:"trust_domain,omitempty"`
	OwnerEmail          string      `json:"owner_email"`
	AgentName           string      `json:"agent_name"`
	EnvProfile          EnvProfile  `json:"env_profile"`
	Status              AgentStatus `json:"status"`
	IsOnline            bool        `json:"is_online"`
	AllowedBinaryHashes []string    `json:"allowed_binary_hashes,omitempty"`
	EnrolledBinaryHash  string      `json:"enrolled_binary_hash,omitempty"`
	PublicKey           string      `json:"public_key,omitempty"`
	Hostname            string      `json:"hostname,omitempty"`
	OS                  string      `json:"os,omitempty"`
	Arch                string      `json:"arch,omitempty"`
	DeviceType          string      `json:"device_type,omitempty"`
	IPAddress           string      `json:"ip_address,omitempty"`
	CreatedAt           time.Time   `json:"created_at"`
	EnrolledAt          *time.Time  `json:"enrolled_at,omitempty"`
	LastGrantAt         *time.Time  `json:"last_grant_at,omitempty"`
	LastHeartbeatAt     *time.Time  `json:"last_heartbeat_at,omitempty"`
	RevokedAt           *time.Time  `json:"revoked_at,omitempty"`
	PermittedScopes     []string    `json:"permitted_scopes,omitempty"`
	UserEmail           string      `json:"user_email,omitempty"`
	Department          string      `json:"department,omitempty"`
	Groups              []string    `json:"groups,omitempty"`
	AuthMode            string      `json:"auth_mode,omitempty"`    // "otc" or "oidc"
	IdPProvider         string      `json:"idp_provider,omitempty"` // "entra", "okta", "generic"
	AgentVersion        string      `json:"agent_version,omitempty"`
	ProtocolVersion     int         `json:"protocol_version,omitempty"`
	Subagents           []string    `json:"subagents,omitempty"`
}

type PreRegisterRequest struct {
	AppID               string     `json:"app_id"`
	OwnerEmail          string     `json:"owner_email"`
	AgentName           string     `json:"agent_name"`
	EnvProfile          EnvProfile `json:"env_profile"`
	AllowedBinaryHashes []string   `json:"allowed_binary_hashes,omitempty"`
	PermittedScopes     []string   `json:"permitted_scopes,omitempty"`
	TTLMins             int        `json:"ttl_minutes,omitempty"`
	MaxInstances        int        `json:"max_instances,omitempty"`
}

type PreRegisterResponse struct {
	AgentID      string    `json:"agent_id"`
	Code         string    `json:"one_time_code"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxInstances int       `json:"max_instances,omitempty"`
}

type RegisterEdgeRequest struct {
	Code            string `json:"one_time_code"`
	BinaryHash      string `json:"binary_hash"`
	PublicKey       string `json:"public_key"`
	Hostname        string `json:"hostname,omitempty"`
	OS              string `json:"os,omitempty"`
	Arch            string `json:"arch,omitempty"`
	InstanceID      string `json:"instance_id,omitempty"`
	AgentVersion    string `json:"agent_version,omitempty"`
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	AssetID         string `json:"asset_id,omitempty"` // hardware-derived machine id, bound at enrollment
}

type RegisterEdgeResponse struct {
	AgentID                  string    `json:"agent_id"`
	AppID                    string    `json:"app_id"`
	InstanceID               string    `json:"instance_id,omitempty"`
	SPIFFEID                 string    `json:"spiffe_id,omitempty"`
	Status                   string    `json:"status"`
	UserEmail                string    `json:"user_email,omitempty"`
	ServerTime               time.Time `json:"server_time"`
	SessionToken             string    `json:"session_token"`
	ServerVersion            string    `json:"server_version,omitempty"`
	MinSupportedAgentVersion string    `json:"min_supported_agent_version,omitempty"`
	PolicyEnrollment
}

type GrantConstraints struct {
	MaxUses   int `json:"max_uses,omitempty"`
	MaxAmount int `json:"max_amount,omitempty"`
}

type AcquireGrantRequest struct {
	AgentID       string            `json:"agent_id"`
	BinaryHash    string            `json:"binary_hash"`
	Signature     string            `json:"signature,omitempty"`
	Timestamp     int64             `json:"timestamp"`
	SessionID     string            `json:"session_id,omitempty"`
	Action        string            `json:"action,omitempty"`
	Resource      string            `json:"resource,omitempty"`
	Constraints   *GrantConstraints `json:"constraints,omitempty"`
	Scopes        []string          `json:"scopes,omitempty"`
	ParentToken   string            `json:"parent_token,omitempty"`
	ParentGrantID string            `json:"parent_grant_id,omitempty"`
	Lineage       []string          `json:"lineage,omitempty"`
}

type AcquireGrantResponse struct {
	Token         string            `json:"token"`
	TokenType     string            `json:"token_type"`
	GrantID       string            `json:"grant_id,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at"`
	TTLSecs       int               `json:"expires_in"`
	Scopes        []string          `json:"scopes"`
	SessionID     string            `json:"session_id,omitempty"`
	Action        string            `json:"action,omitempty"`
	Resource      string            `json:"resource,omitempty"`
	PolicyVersion string            `json:"policy_version,omitempty"`
	Constraints   *GrantConstraints `json:"constraints,omitempty"`
	ParentGrantID string            `json:"parent_grant_id,omitempty"`
	RootGrantID   string            `json:"root_grant_id,omitempty"`
	RootAgentID   string            `json:"root_agent_id,omitempty"`
	Lineage       []string          `json:"lineage,omitempty"`
	LineageTree   string            `json:"lineage_tree,omitempty"`
	Depth         int               `json:"depth,omitempty"`
}

// DelegateGrantRequest models requests to mint an attenuated child grant (BAP-532).
type DelegateGrantRequest struct {
	ParentToken     string            `json:"parent_token"`
	ParentGrantID   string            `json:"parent_grant_id,omitempty"`
	ChildAgentID    string            `json:"child_agent_id"`
	ChildAppID      string            `json:"child_app_id,omitempty"`
	SessionID       string            `json:"session_id,omitempty"`
	RequestedScopes []string          `json:"requested_scopes,omitempty"`
	Scopes          []string          `json:"scopes,omitempty"`
	Action          string            `json:"action,omitempty"`
	Resource        string            `json:"resource,omitempty"`
	Constraints     *GrantConstraints `json:"constraints,omitempty"`
	TTLMins         int               `json:"ttl_minutes,omitempty"`
}

// DelegateGrantResponse returns the attenuated child grant and delegation lineage (BAP-532).
type DelegateGrantResponse struct {
	Token         string    `json:"token"`
	TokenType     string    `json:"token_type"`
	GrantID       string    `json:"grant_id"`
	ParentGrantID string    `json:"parent_grant_id"`
	RootGrantID   string    `json:"root_grant_id"`
	RootAgentID   string    `json:"root_agent_id"`
	ParentAgentID string    `json:"parent_agent_id"`
	Lineage       []string  `json:"lineage"`
	LineageTree   string    `json:"lineage_tree"`
	ExpiresAt     time.Time `json:"expires_at"`
	TTLSecs       int       `json:"expires_in"`
	Scopes        []string  `json:"scopes"`
	SessionID     string    `json:"session_id,omitempty"`
	Action        string    `json:"action,omitempty"`
	Resource      string    `json:"resource,omitempty"`
	Depth         int       `json:"depth"`
}

// DevOTCRequest allows unauthenticated developers in dev mode to request an instant OTC.
type DevOTCRequest struct {
	AppID      string `json:"app_id,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	OwnerEmail string `json:"owner_email,omitempty"`
	AgentName  string `json:"agent_name,omitempty"`
}

type DevOTCResponse struct {
	AgentID   string    `json:"agent_id"`
	Code      string    `json:"one_time_code"`
	ExpiresAt time.Time `json:"expires_at"`
	Mode      string    `json:"mode"`
}

// OIDC Device Flow Types (RFC 8628)
type OIDCDeviceCodeRequest struct {
	ClientID   string `json:"client_id"`
	Scope      string `json:"scope,omitempty"`
	Provider   string `json:"provider,omitempty"` // "entra", "okta", "generic"
	Hostname   string `json:"hostname,omitempty"`
	BinaryHash string `json:"binary_hash,omitempty"`
	AppID      string `json:"app_id,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
}

type OIDCDeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type OIDCDeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
	// AssetID is the machine's hardware-derived id, recorded against the enrolled workstation
	// identity so signed policy is scoped to the machine, not just the login.
	AssetID string `json:"asset_id,omitempty"`
}

// PolicyEnrollment carries the signed-policy trust anchor handed out during authenticated
// enrollment (OTC or OIDC). The client pins it; no separate key step exists for the user.
type PolicyEnrollment struct {
	PolicyAssetID   string `json:"policy_asset_id,omitempty"`
	PolicyKeyID     string `json:"policy_key_id,omitempty"`
	PolicyPublicKey string `json:"policy_public_key,omitempty"`
}

type OIDCDeviceTokenResponse struct {
	Status       string   `json:"status"` // "pending", "authorized", "expired"
	Error        string   `json:"error,omitempty"`
	IDToken      string   `json:"id_token,omitempty"`
	AccessToken  string   `json:"access_token,omitempty"`
	UserEmail    string   `json:"user_email,omitempty"`
	Department   string   `json:"department,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	AgentID      string   `json:"agent_id,omitempty"`
	AppID        string   `json:"app_id,omitempty"`
	InstanceID   string   `json:"instance_id,omitempty"`
	SessionToken string   `json:"session_token,omitempty"`
	ExpiresIn    int      `json:"expires_in,omitempty"`
	Provider     string   `json:"provider,omitempty"`
	PolicyEnrollment
}

type OIDCDeviceVerifyRequest struct {
	UserCode   string   `json:"user_code"`
	UserEmail  string   `json:"user_email"`
	Department string   `json:"department"`
	Groups     []string `json:"groups"`
	Provider   string   `json:"provider,omitempty"`
}

// OIDCConfig defines configurable Enterprise Identity Provider parameters.
type OIDCConfig struct {
	Enabled         bool     `json:"enabled"`
	Provider        string   `json:"provider"`                   // "entra", "okta", "generic"
	IssuerURL       string   `json:"issuer_url,omitempty"`       // e.g. https://login.microsoftonline.com/{tenant_id}/v2.0
	ClientID        string   `json:"client_id,omitempty"`        // OAuth2 client_id
	ClientSecret    string   `json:"client_secret,omitempty"`    // Optional for confidential clients
	DeviceAuthURL   string   `json:"device_auth_url,omitempty"`  // Device Authorization Endpoint
	TokenURL        string   `json:"token_url,omitempty"`        // Token Endpoint
	VerificationURI string   `json:"verification_uri,omitempty"` // User verification web page
	Scopes          []string `json:"scopes,omitempty"`           // e.g. ["openid", "profile", "email", "groups"]
	TenantID        string   `json:"tenant_id,omitempty"`        // Entra Tenant ID or Okta org
	AllowedDomains  []string `json:"allowed_domains,omitempty"`  // e.g. ["corp.com", "enterprise.org"]
	ClaimDepartment string   `json:"claim_department,omitempty"` // Claim key for department (default: "department")
	ClaimGroups     string   `json:"claim_groups,omitempty"`     // Claim key for groups (default: "groups")
	ClaimEmail      string   `json:"claim_email,omitempty"`      // Claim key for email (default: "email")
}

// SaaS Delegated Token Governance Types (BAP-539)
type BindSaaSTokenRequest struct {
	Provider   string   `json:"provider"`
	TokenID    string   `json:"token_id,omitempty"`
	SessionID  string   `json:"session_id"`
	AgentID    string   `json:"agent_id"`
	UserEmail  string   `json:"user_email,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
}

type VerifySaaSTokenRequest struct {
	TokenID         string `json:"token_id"`
	CallerSessionID string `json:"caller_session_id"`
	RequestedScope  string `json:"requested_scope,omitempty"`
}

type VerifySaaSTokenResponse struct {
	Allowed bool   `json:"allowed"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

// Immutable Intent Attestation Types (BAP-561)
type AttestIntentRequest struct {
	TaskID            string   `json:"task_id"`
	SessionID         string   `json:"session_id"`
	RootOperatorEmail string   `json:"root_operator_email,omitempty"`
	GoalDescription   string   `json:"goal_description"`
	PermittedEnvs     []string `json:"permitted_envs,omitempty"`
	PermittedActions  []string `json:"permitted_actions,omitempty"`
	TTLSeconds        int      `json:"ttl_seconds,omitempty"`
}

type VerifyIntentRequest struct {
	TaskID          string `json:"task_id"`
	AttemptedAction string `json:"attempted_action"`
	TargetEnv       string `json:"target_env,omitempty"`
}

type VerifyIntentResponse struct {
	Allowed bool   `json:"allowed"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

// Task-Scoped HITL Step-Up Escalation Types (BAP-565)
type StepUpEscalationRequest struct {
	TaskID    string `json:"task_id"`
	SessionID string `json:"session_id"`
	AgentID   string `json:"agent_id"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
}

type StepUpResolveRequest struct {
	EscalationID  string `json:"escalation_id"`
	Decision      string `json:"decision"` // "approve" or "deny"
	ReviewerEmail string `json:"reviewer_email,omitempty"`
	TTLSeconds    int    `json:"ttl_seconds,omitempty"`
}

// RFC 8693 OAuth 2.0 Security Token Service (STS) Types (BAP-810)
const (
	RFC8693GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	RFC8693TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	RFC8693TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	RFC8693TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	RFC8693TokenTypeSVID          = "urn:ietf:params:oauth:token-type:svid"
)

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
	MaxUses            int    `json:"max_uses,omitempty"`
}

type RFC8693TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"` // "Bearer"
	ExpiresIn       int    `json:"expires_in"` // seconds (e.g. 300)
	Scope           string `json:"scope,omitempty"`
}

type OBOTokenExchangeRecord struct {
	ExchangeID      string    `json:"exchange_id"`
	Timestamp       time.Time `json:"timestamp"`
	SubjectSVID     string    `json:"subject_svid"`
	ActorSVID       string    `json:"actor_svid,omitempty"`
	UserEmail       string    `json:"user_email"`
	Audience        string    `json:"audience"`
	RequestedScope  string    `json:"requested_scope"`
	AttenuatedScope string    `json:"attenuated_scope"`
	BoundSessionID  string    `json:"bound_session_id"`
	TokenID         string    `json:"token_id"`
	Status          string    `json:"status"` // "ACTIVE", "BURNED", "DENIED", "EXPIRED", "REVOKED"
	DecisionReason  string    `json:"decision_reason,omitempty"`
}

// BAP-900 Series Types: Intelligent Authorization, Credential Isolation & Zero-Trust Execution

// AgentPrincipal represents an identifiable agent principal distinct from its human owner and workstation runtime (BAP-911).
type AgentPrincipal struct {
	PrincipalID    string    `json:"principal_id"`     // urn:bap:principal:agent:<uuid>
	AgentSessionID string    `json:"agent_session_id"` // Bound session ID
	ClientType     string    `json:"client_type"`      // "claude-code", "copilot", "antigravity", "codex", "opencode"
	HumanOwner     string    `json:"human_owner"`      // Windows user / SSO email
	WorkstationID  string    `json:"workstation_id"`   // Physical or virtual workstation ID
	PrincipalSVID  string    `json:"principal_svid"`   // spiffe://bap.internal/principal/<principal_id>
	Status         string    `json:"status"`           // "active", "idle", "suspended", "terminated"
	Permissions    []string  `json:"permissions"`      // Currently granted attenuated permissions
	CreatedAt      time.Time `json:"created_at"`
	LastActiveAt   time.Time `json:"last_active_at"`
}

// SensitivityLevel represents data classification tier for sensitivity-aware authorization (BAP-906).
type SensitivityLevel string

const (
	SensitivityPublic       SensitivityLevel = "PUBLIC"
	SensitivityInternal     SensitivityLevel = "INTERNAL"
	SensitivityConfidential SensitivityLevel = "CONFIDENTIAL"
	SensitivityRestricted   SensitivityLevel = "RESTRICTED"
)

// DecisionType represents the common decision contract for policy evaluation (BAP-902).
type DecisionType string

const (
	DecisionAllow           DecisionType = "ALLOW"
	DecisionDeny            DecisionType = "DENY"
	DecisionNarrow          DecisionType = "NARROW"
	DecisionRequireApproval DecisionType = "REQUIRE_APPROVAL"
)

// PermissionPlan represents a least-privilege proposal generated from agent intent (BAP-901).
type PermissionPlan struct {
	PlanID            string           `json:"plan_id"`
	SessionID         string           `json:"session_id"`
	PrincipalID       string           `json:"principal_id"`
	DeclaredIntent    string           `json:"declared_intent"`
	RequestedActions  []string         `json:"requested_actions"`
	RequestedResources []string        `json:"requested_resources"`
	ApprovedActions   []string         `json:"approved_actions,omitempty"`
	ApprovedResources []string         `json:"approved_resources,omitempty"`
	Decision          DecisionType     `json:"decision"`
	NarrowingApplied  bool             `json:"narrowing_applied"`
	NarrowingReason   string           `json:"narrowing_reason,omitempty"`
	SensitivityLevel  SensitivityLevel `json:"sensitivity_level"`
	RequiresApproval  bool             `json:"requires_approval"`
	ApprovalTicketID  string           `json:"approval_ticket_id,omitempty"`
	DeterministicRule string           `json:"deterministic_rule"`
	CreatedAt         time.Time        `json:"created_at"`
}

// NetworkControlChannel documents a communication path across BAP infrastructure (BAP-912).
type NetworkControlChannel struct {
	ChannelID          string `json:"channel_id"`
	Name               string `json:"name"`
	Source             string `json:"source"`
	Destination        string `json:"destination"`
	Direction          string `json:"direction"` // "outbound", "inbound", "bidirectional", "local_ipc"
	Protocol           string `json:"protocol"`  // "IPC/NamedPipe", "HTTPS/REST", "HTTPS/SSE", "mTLS/gRPC", "RFC8693"
	Authentication     string `json:"authentication"`
	Encryption         string `json:"encryption"`
	Purpose            string `json:"purpose"`
	FailureBehavior    string `json:"failure_behavior"`    // "fail-closed", "fail-safe-cached", "fail-closed-offline"
	RevocationBehavior string `json:"revocation_behavior"` // "immediate-kill", "token-burn", "sse-disconnect"
	RestartBehavior    string `json:"restart_behavior"`    // "re-attest-session", "re-authenticate-idp"
}

// LLMCallGovernance documents model calls and enforces non-reliance invariant (BAP-914).
type LLMCallGovernance struct {
	CallID              string           `json:"call_id"`
	Purpose             string           `json:"purpose"` // "intent_evaluation", "permission_planning", "content_sanitization"
	ModelProvider       string           `json:"model_provider"`
	ModelName           string           `json:"model_name"`
	DataClassification  SensitivityLevel `json:"data_classification"`
	TrustBoundary       string           `json:"trust_boundary"`
	AuthorizationPolicy string           `json:"authorization_policy"`
	AuditCorrelationID  string           `json:"audit_correlation_id"`
	NonRelianceVerified bool             `json:"non_reliance_verified"` // True: deterministic policy validates recommendation
}

// CryptographicAgentSVID represents a signed workload identity assertion bound to a human owner (BAP-915).
type CryptographicAgentSVID struct {
	Issuer          string    `json:"iss"`
	Subject         string    `json:"sub"` // spiffe://bap.internal/.../principal/<principal_id>
	HumanOwner      string    `json:"human_owner"`
	HumanOIDCSUB    string    `json:"human_oidc_sub,omitempty"`
	WorkstationID   string    `json:"workstation_id"`
	SessionID       string    `json:"session_id"`
	ClientType      string    `json:"client_type"` // claude-code, copilot, etc.
	PublicKeyHex    string    `json:"public_key_hex"`
	IssuedAt        time.Time `json:"iat"`
	ExpiresAt       time.Time `json:"exp"`
	IssuerSignature string    `json:"issuer_signature"`
}

// DelegationIdentity captures who authorized the task execution (BAP-916).
type DelegationIdentity struct {
	DelegationType        string `json:"delegation_type"` // "human_interactive_prompt", "automated_workflow", "step_up_approval"
	HumanTokenOrSignature string `json:"human_token_or_signature,omitempty"`
	ApprovalTicketID      string `json:"approval_ticket_id,omitempty"`
	ApproverEmail         string `json:"approver_email,omitempty"`
}

// TaskIntent captures declared task mission and prompt hash (BAP-916).
type TaskIntent struct {
	PrimaryMission string `json:"primary_mission"` // BUG_FIX, INVESTIGATION, etc.
	DeclaredGoal   string `json:"declared_goal"`
	PromptHash     string `json:"prompt_hash"`
}

// PermissionAsk specifies requested actions and resources (BAP-916).
type PermissionAsk struct {
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

// TaskAuthorizationEnvelope represents the atomic 4-tuple zero-trust request contract (BAP-916).
// Tuple: (Who, AuthorizedBy, Intent, PermissionAsk) signed by the agent's cryptographic key.
type TaskAuthorizationEnvelope struct {
	EnvelopeID     string                 `json:"envelope_id"`
	Identity       CryptographicAgentSVID `json:"identity"`        // 1. Who you are
	AuthorizedBy   DelegationIdentity     `json:"authorized_by"`   // 2. Who authorized this
	Intent         TaskIntent             `json:"intent"`          // 3. What is the declared intent
	PermissionAsk  PermissionAsk          `json:"permission_ask"`  // 4. Asked permissions (starting set = 0)
	EnvelopeHash   string                 `json:"envelope_hash"`   // SHA-256 of canonical fields
	AgentSignature string                 `json:"agent_signature"` // Ed25519 signature by Agent private key
	Timestamp      time.Time              `json:"timestamp"`
}

// TaskGrant represents an ephemeral, task-scoped grant token with zero standing privilege (BAP-917).
type TaskGrant struct {
	GrantID            string    `json:"grant_id"`
	EnvelopeID         string    `json:"envelope_id"`
	SessionID          string    `json:"session_id"`
	PrincipalSVID      string    `json:"principal_svid"`
	HumanOwner         string    `json:"human_owner"`
	AllowedActions     []string  `json:"allowed_actions"`
	AllowedResources   []string  `json:"allowed_resources"`
	MaxUses            int       `json:"max_uses"`
	RemainingUses      int       `json:"remaining_uses"`
	ExpiresAt          time.Time `json:"expires_at"`
	IssuedAt           time.Time `json:"issued_at"`
	IsBurned           bool      `json:"is_burned"`
	BurnReason         string    `json:"burn_reason,omitempty"`
	AuthoritySignature string    `json:"authority_signature"` // Signed by BAP Local PEP
}

// AuditLineageProof provides mathematical non-repudiation linking the full execution chain (BAP-918).
type AuditLineageProof struct {
	ProofID            string    `json:"proof_id"`
	SessionID          string    `json:"session_id"`
	HumanOwner         string    `json:"human_owner"`
	AgentPrincipalSVID string    `json:"agent_principal_svid"`
	IntentMission      string    `json:"intent_mission"`
	GrantID            string    `json:"grant_id"`
	CommandExecuted    string    `json:"command_executed"`
	ExecutedBinaryHash string    `json:"executed_binary_hash"`
	ProcessAncestry    []string  `json:"process_ancestry"`
	DecisionResult     string    `json:"decision_result"`
	Timestamp          time.Time `json:"timestamp"`
	LedgerSignature    string    `json:"ledger_signature"`
}



