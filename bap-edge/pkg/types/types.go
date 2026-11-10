package types

import "time"

// AttestationResponse is returned by the attestation server when verification succeeds.
type AttestationResponse struct {
	Token string `json:"token"`
}

// ExecutionReceipt represents the cryptographic provenance record of an executed or evaluated action.
type ExecutionReceipt struct {
	ReceiptID      string    `json:"receipt_id"`
	RequestHash    string    `json:"request_hash"`
	Identity       string    `json:"identity"`
	Delegation     string    `json:"delegation"`
	PolicyVersion  string    `json:"policy_version"`
	PolicyHash     string    `json:"policy_hash,omitempty"`
	SandboxProfile string    `json:"sandbox_profile"`
	SessionID      string    `json:"session_id,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	Result         string    `json:"result"` // e.g. "ALLOWED_EXECUTED", "DENIED_POLICY", "DENIED_TAMPER", "EXECUTION_FAILED", "DECISION_ONLY"

	// Delegation Lineage & Attenuation (BAP-532)
	Lineage       []string `json:"lineage,omitempty"`
	LineageTree   string   `json:"lineage_tree,omitempty"`
	RootAgentID   string   `json:"root_agent_id,omitempty"`
	ParentGrantID string   `json:"parent_grant_id,omitempty"`
	GrantID       string   `json:"grant_id,omitempty"`

	// Identity-Aware Egress Control (BAP-530)
	DestinationTenantID string `json:"destination_tenant_id,omitempty"`

	// Process-Level Supervision & Child Ancestry Tracking (BAP-534)
	ProcessTree []string `json:"process_tree,omitempty"`
	ParentPID   int      `json:"parent_pid,omitempty"`
	ProcessPID  int      `json:"process_pid,omitempty"`

	// Caller Lineage & Workload Attestation
	CallerBinary string `json:"caller_binary,omitempty"`
	CallerHash   string `json:"caller_hash,omitempty"`
}

// ExecResponse is output by the exec command.
type ExecResponse struct {
	Allowed           bool              `json:"allowed"`
	Decision          string            `json:"decision,omitempty"`
	Output            string            `json:"output,omitempty"`
	ExitCode     int               `json:"exit_code"`
	Reason       string            `json:"reason,omitempty"`
	Suggestion   string            `json:"suggestion,omitempty"`
	Warning      string            `json:"warning,omitempty"`
	Mode         string            `json:"mode,omitempty"`
	DecisionOnly      bool              `json:"decision_only,omitempty"`
	StepUpDecision    string            `json:"step_up_decision,omitempty"`
	CanonicalAction   string            `json:"canonical_action,omitempty"`
	CanonicalResource string            `json:"canonical_resource,omitempty"`
	Receipt           *ExecutionReceipt `json:"receipt,omitempty"`
}

// PluginState represents the observable lifecycle state of an agent plugin (BAP-806).
type PluginState string

const (
	PluginStateInstalled   PluginState = "Installed"
	PluginStateActive      PluginState = "Active"
	PluginStateDegraded    PluginState = "Degraded"
	PluginStateDisabled    PluginState = "Disabled"
	PluginStateMissing     PluginState = "Missing"
	PluginStateUnsupported PluginState = "Unsupported"
	PluginStateUnknown     PluginState = "Unknown"
)

// PluginHealthRecord captures observable evidence for an agent plugin.
type PluginHealthRecord struct {
	Client              string      `json:"client"`                 // "claude-code" or "copilot"
	PluginName          string      `json:"plugin_name"`            // e.g. "bap-zero-trust"
	PluginVersion       string      `json:"plugin_version"`         // e.g. "1.0.0"
	State               PluginState `json:"state"`                  // Active, Installed, Degraded, etc.
	ManifestPath        string      `json:"manifest_path,omitempty"`
	AgentDiscovered     bool        `json:"agent_discovered"`
	PluginInstalled     bool        `json:"plugin_installed"`
	HookActive          bool        `json:"hook_active"`
	EnforcementVerified bool        `json:"enforcement_verified"`
	LastObservedAt      *time.Time  `json:"last_observed_at,omitempty"`
	PolicyVersion       string      `json:"policy_version,omitempty"`
}

// DefenseLayerStatus represents the status of a specific security layer in BAP's defense-in-depth model.
type DefenseLayerStatus struct {
	LayerID     string `json:"layer_id"`     // e.g. "Layer 1A", "Layer 1B", "Layer 2", etc.
	Name        string `json:"name"`         // e.g. "Native Agent Plugin"
	Description string `json:"description"`  // e.g. "Vendor plugin framework hook interception"
	Status      string `json:"status"`       // "ACTIVE", "OPTIONAL", "DEGRADED", "DISABLED"
	Evidence    string `json:"evidence"`
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
	PlanID             string           `json:"plan_id"`
	SessionID          string           `json:"session_id"`
	PrincipalID        string           `json:"principal_id"`
	DeclaredIntent     string           `json:"declared_intent"`
	RequestedActions   []string         `json:"requested_actions"`
	RequestedResources []string         `json:"requested_resources"`
	ApprovedActions    []string         `json:"approved_actions,omitempty"`
	ApprovedResources  []string         `json:"approved_resources,omitempty"`
	Decision           DecisionType     `json:"decision"`
	NarrowingApplied   bool             `json:"narrowing_applied"`
	NarrowingReason    string           `json:"narrowing_reason,omitempty"`
	SensitivityLevel   SensitivityLevel `json:"sensitivity_level"`
	RequiresApproval   bool             `json:"requires_approval"`
	ApprovalTicketID   string           `json:"approval_ticket_id,omitempty"`
	DeterministicRule  string           `json:"deterministic_rule"`
	CreatedAt          time.Time        `json:"created_at"`
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
	NonRelianceVerified bool             `json:"non_reliance_verified"`
}

// CryptographicAgentSVID represents a signed workload identity assertion bound to a human owner (BAP-915).
type CryptographicAgentSVID struct {
	Issuer         string    `json:"iss"`
	Subject        string    `json:"sub"` // spiffe://bap.internal/.../principal/<principal_id>
	HumanOwner     string    `json:"human_owner"`
	HumanOIDCSUB   string    `json:"human_oidc_sub,omitempty"`
	WorkstationID  string    `json:"workstation_id"`
	SessionID      string    `json:"session_id"`
	ClientType     string    `json:"client_type"` // claude-code, copilot, etc.
	PublicKeyHex   string    `json:"public_key_hex"`
	IssuedAt       time.Time `json:"iat"`
	ExpiresAt      time.Time `json:"exp"`
	IssuerSignature string   `json:"issuer_signature"`
}

// DelegationIdentity captures who authorized the task execution (BAP-916).
type DelegationIdentity struct {
	DelegationType          string `json:"delegation_type"` // "human_interactive_prompt", "automated_workflow", "step_up_approval"
	HumanTokenOrSignature   string `json:"human_token_or_signature,omitempty"`
	ApprovalTicketID        string `json:"approval_ticket_id,omitempty"`
	ApproverEmail           string `json:"approver_email,omitempty"`
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
	GrantID           string    `json:"grant_id"`
	EnvelopeID        string    `json:"envelope_id"`
	SessionID         string    `json:"session_id"`
	PrincipalSVID     string    `json:"principal_svid"`
	HumanOwner        string    `json:"human_owner"`
	AllowedActions    []string  `json:"allowed_actions"`
	AllowedResources  []string  `json:"allowed_resources"`
	MaxUses           int       `json:"max_uses"`
	RemainingUses     int       `json:"remaining_uses"`
	ExpiresAt         time.Time `json:"expires_at"`
	IssuedAt          time.Time `json:"issued_at"`
	IsBurned          bool      `json:"is_burned"`
	BurnReason        string    `json:"burn_reason,omitempty"`
	AuthoritySignature string   `json:"authority_signature"` // Signed by BAP Local PEP
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



