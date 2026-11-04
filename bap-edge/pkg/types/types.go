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

