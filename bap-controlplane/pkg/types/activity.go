package types

import "time"

// AgentActivityEvent is the canonical representation of agent activity across the enterprise (BAP-521).
type AgentActivityEvent struct {
	Timestamp          string    `json:"timestamp"`
	SessionID          string    `json:"session_id"`
	AgentID            string    `json:"agent_id"`
	AgentType          string    `json:"agent_type"`
	RuntimeID          string    `json:"runtime_id"`
	UserID             string    `json:"user_id"`
	BusinessUnit       string    `json:"business_unit"`
	Application        string    `json:"application"`
	PromptID           string    `json:"prompt_id"`
	PromptSummary      string    `json:"prompt_summary"`
	Intent             string    `json:"intent"`
	IntentCategory     string    `json:"intent_category"`
	Action             string    `json:"action"`
	Tool               string    `json:"tool"`
	TargetResource     string    `json:"target_resource"`
	DataClassification string    `json:"data_classification"`
	PolicyDecision     string    `json:"policy_decision"`
	RiskScore          float64   `json:"risk_score"`
	GrantID            string    `json:"grant_id"`
	GrantScope         string    `json:"grant_scope"`
	GrantTTL           int       `json:"grant_ttl"`
	ActionStatus       string    `json:"action_status"`    // "working", "waiting", "completed", "denied", "failed"
	OutcomeCategory    string    `json:"outcome_category"` // "Success", "Blocked", "Exception", "Timeout"
	TraceID            string    `json:"trace_id"`
	DeviationLevel     string    `json:"deviation_level,omitempty"`  // "NONE", "LOW", "MEDIUM", "CRITICAL"
	DeviationReason    string    `json:"deviation_reason,omitempty"`
}

// ActivitySummary contains high-level KPIs for CIO / persona dashboards (BAP-522, BAP-523).
type ActivitySummary struct {
	TotalActiveAgents    int            `json:"total_active_agents"`
	GovernedAgentUsers   int            `json:"governed_agent_users"`
	WorkIntentsCompleted int            `json:"work_intents_completed"`
	BusinessUnitsActive  string         `json:"business_units_active"`
	GovernedPercent      float64        `json:"governed_percent"`
	HighRiskPrevented    int            `json:"high_risk_prevented"`
	DepartmentMix        map[string]int `json:"department_mix"`
	IntentMix            map[string]int `json:"intent_mix"`
	OutcomePulse         map[string]int `json:"outcome_pulse"`
	Timestamp            string         `json:"timestamp"`
}

// IntentDrillDown represents category sub-breakdowns for CIO drill-down (BAP-523).
type IntentDrillDown struct {
	Category string         `json:"category"`
	Share    float64        `json:"share"`
	Subtypes map[string]int `json:"subtypes"`
}

// BusinessUnitTopologyNode represents a branch in the enterprise activity topology (BAP-524).
type BusinessUnitTopologyNode struct {
	ID             string                      `json:"id"`
	Name           string                      `json:"name"`
	Type           string                      `json:"type"` // "root", "division", "team", "agent_platform"
	ActiveSessions int                         `json:"active_sessions"`
	RiskPosture    string                      `json:"risk_posture"` // "healthy", "warning", "critical"
	Children       []*BusinessUnitTopologyNode `json:"children,omitempty"`
	PlatformCounts map[string]int              `json:"platform_counts,omitempty"`
}

// IntentDeviationReport models the Intent -> Action contract evaluation (BAP-525).
type IntentDeviationReport struct {
	SessionID      string    `json:"session_id"`
	Intent         string    `json:"intent"`
	IntentCategory string    `json:"intent_category"`
	DeclaredPlan   string    `json:"declared_plan"`
	RequestedTool  string    `json:"requested_tool"`
	TargetResource string    `json:"target_resource"`
	ObservedAction string    `json:"observed_action"`
	DeviationLevel string    `json:"deviation_level"` // "NONE", "LOW", "MEDIUM", "CRITICAL"
	IsDeviated     bool      `json:"is_deviated"`
	Reason         string    `json:"reason"`
	PolicyDecision string    `json:"policy_decision"`
	Timestamp      time.Time `json:"timestamp"`
}
