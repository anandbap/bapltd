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
}

// ExecResponse is output by the exec command.
type ExecResponse struct {
	Allowed      bool              `json:"allowed"`
	Output       string            `json:"output,omitempty"`
	ExitCode     int               `json:"exit_code"`
	Reason       string            `json:"reason,omitempty"`
	Suggestion   string            `json:"suggestion,omitempty"`
	Warning      string            `json:"warning,omitempty"`
	Mode         string            `json:"mode,omitempty"`
	DecisionOnly      bool              `json:"decision_only,omitempty"`
	CanonicalAction   string            `json:"canonical_action,omitempty"`
	CanonicalResource string            `json:"canonical_resource,omitempty"`
	Receipt           *ExecutionReceipt `json:"receipt,omitempty"`
}
