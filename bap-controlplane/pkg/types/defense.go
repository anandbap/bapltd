package types

// DefenseObservation is evidence from a check that actually ran. It conveys no authority.
type DefenseObservation struct {
	EventID        string `json:"event_id"`
	ActionID       string `json:"action_id"`
	Layer          int    `json:"layer"`
	Producer       string `json:"producer"`
	Decision       string `json:"decision"`
	Timestamp      string `json:"timestamp"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Diagnostic     bool   `json:"diagnostic,omitempty"`
	OverrideActive bool   `json:"developer_override_active,omitempty"`
}
