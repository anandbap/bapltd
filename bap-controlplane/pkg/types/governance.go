package types

import "time"

type ActionLifecycleState string

const (
	StateProposed    ActionLifecycleState = "PROPOSED"
	StateEvaluating  ActionLifecycleState = "EVALUATING"
	StateAuthorized  ActionLifecycleState = "AUTHORIZED"
	StateGranted     ActionLifecycleState = "GRANTED"
	StatePresented   ActionLifecycleState = "PRESENTED"
	StatePEPAllowed  ActionLifecycleState = "PEP_ALLOWED"
	StateExecuting   ActionLifecycleState = "EXECUTING"
	StateCommitted   ActionLifecycleState = "COMMITTED"
	StateCompleted   ActionLifecycleState = "COMPLETED"
	StateDenied      ActionLifecycleState = "DENIED"
	StateFailed      ActionLifecycleState = "FAILED"
	StateExpired     ActionLifecycleState = "EXPIRED"
	StateRevoked     ActionLifecycleState = "REVOKED"
	StateInterrupted ActionLifecycleState = "INTERRUPTED"
	StateUnknown     ActionLifecycleState = "UNKNOWN"
)

type AdminRole string

const (
	RoleObserver    AdminRole = "Observer"
	RoleOperator    AdminRole = "Operator"
	RoleApprover    AdminRole = "Approver"
	RolePolicyAdmin AdminRole = "PolicyAdmin"
)

type StateTransition struct {
	From      ActionLifecycleState `json:"from"`
	To        ActionLifecycleState `json:"to"`
	Timestamp time.Time            `json:"timestamp"`
	Actor     string               `json:"actor"`
	Reason    string               `json:"reason"`
}

type ActionProposal struct {
	ProposalID        string               `json:"proposal_id"`
	ParentProposalID  string               `json:"parent_proposal_id,omitempty"`
	TraceID           string               `json:"trace_id"`
	AgentID           string               `json:"agent_id"`
	SessionID         string               `json:"session_id"`
	TaskID            string               `json:"task_id"`
	HumanID           string               `json:"human_id"`
	Intent            string               `json:"intent"`
	Action            string               `json:"action"`
	Resource          string               `json:"resource"`
	Parameters        map[string]any       `json:"parameters,omitempty"`
	State             ActionLifecycleState `json:"state"`
	StateHistory      []StateTransition    `json:"state_history,omitempty"`
	PolicyVersion     string               `json:"policy_version,omitempty"`
	Decision          string               `json:"decision,omitempty"`
	DecisionReason    string               `json:"decision_reason,omitempty"`
	GrantID           string               `json:"grant_id,omitempty"`
	PEPDecision       string               `json:"pep_decision,omitempty"`
	ExecutionStatus   string               `json:"execution_status,omitempty"`
	ApproverID        string               `json:"approver_id,omitempty"`
	ApprovalReason    string               `json:"approval_reason,omitempty"`
	RemediatedBy      string               `json:"remediated_by,omitempty"`
	RemediationReason string               `json:"remediation_reason,omitempty"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
}

type SubmitProposalRequest struct {
	AgentID    string         `json:"agent_id"`
	SessionID  string         `json:"session_id"`
	TaskID     string         `json:"task_id"`
	HumanID    string         `json:"human_id"`
	Intent     string         `json:"intent"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	Parameters map[string]any `json:"parameters,omitempty"`
	TraceID    string         `json:"trace_id,omitempty"`
}

type RemediateProposalRequest struct {
	OperatorID string         `json:"operator_id"`
	Reason     string         `json:"reason"`
	Action     string         `json:"action,omitempty"`
	Resource   string         `json:"resource,omitempty"`
	Parameters map[string]any `json:"parameters,omitempty"`
	Intent     string         `json:"intent,omitempty"`
}

type TransitionStateRequest struct {
	ToState ActionLifecycleState `json:"to_state"`
	Actor   string               `json:"actor"`
	Reason  string               `json:"reason"`
}

type ApproveProposalRequest struct {
	ApproverID string `json:"approver_id"`
	Reason     string `json:"reason"`
}

type AdminActionRequest struct {
	AdminID string         `json:"admin_id"`
	Role    AdminRole      `json:"role"`
	Action  string         `json:"action"`
	Target  string         `json:"target"`
	Details map[string]any `json:"details,omitempty"`
	TraceID string         `json:"trace_id,omitempty"`
}

type SimulationRequest struct {
	AgentID    string         `json:"agent_id"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	Intent     string         `json:"intent,omitempty"`
	Parameters map[string]any `json:"parameters,omitempty"`
	Expected   string         `json:"expected,omitempty"`
}

type SimulationResponse struct {
	EvaluationResult string `json:"evaluation_result"`
	PolicyVersion    string `json:"policy_version"`
	MatchExpected    bool   `json:"match_expected"`
	Reason           string `json:"reason"`
	IsTest           bool   `json:"is_test"`
}

type EvidenceNode struct {
	Stage     string    `json:"stage"`
	NodeID    string    `json:"node_id"`
	Details   any       `json:"details"`
	Timestamp time.Time `json:"timestamp"`
	Hash      string    `json:"hash"`
}

type InvestigationTimelineResponse struct {
	ProposalID   string               `json:"proposal_id"`
	TaskID       string               `json:"task_id"`
	RootProposal string               `json:"root_proposal_id"`
	CurrentState ActionLifecycleState `json:"current_state"`
	Nodes        []EvidenceNode       `json:"nodes"`
	Lineage      []string             `json:"lineage"`
	Siblings     []string             `json:"siblings,omitempty"`
}

type ReconciliationReport struct {
	UnpresentedGrants []string `json:"unpresented_grants"`
	UnconfirmedExecs  []string `json:"unconfirmed_executions"`
	ReconciledCount   int      `json:"reconciled_count"`
}
