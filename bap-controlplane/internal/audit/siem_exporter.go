package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SIEMEvent represents a security event normalized for SOC ingestion (BAP-722).
type SIEMEvent struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	EventType   string    `json:"event_type"` // e.g. "POLICY_DENIAL", "CANARY_TRIPPED", "BYPASS_ATTEMPT", "STEPUP_ESCALATION"
	AgentID     string    `json:"agent_id"`
	SessionID   string    `json:"session_id"`
	TaskID      string    `json:"task_id,omitempty"`
	Principal   string    `json:"principal,omitempty"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	Decision    string    `json:"decision"` // "ALLOW", "DENY", "STEPUP"
	Reason      string    `json:"reason"`
	PolicyVer   string    `json:"policy_version"`
	TraceID     string    `json:"trace_id,omitempty"`
}

// SIEMExporter manages event formatting into CEF/Syslog and webhook dispatching.
type SIEMExporter struct {
	mu         sync.RWMutex
	webhookURL string
	events     []SIEMEvent
	client     *http.Client
}

// NewSIEMExporter creates an initialized SIEM exporter.
func NewSIEMExporter(webhookURL string) *SIEMExporter {
	return &SIEMExporter{
		webhookURL: webhookURL,
		events:     make([]SIEMEvent, 0, 100),
		client:     &http.Client{Timeout: 5 * time.Second},
	}
}

// RecordEvent buffers a security event for SOC export.
func (e *SIEMExporter) RecordEvent(evt SIEMEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}
	e.events = append(e.events, evt)
	if len(e.events) > 500 {
		e.events = e.events[1:] // retain ring buffer of recent events
	}
}

// FormatCEF converts a SIEMEvent into ArcSight Common Event Format (CEF:0).
func FormatCEF(evt SIEMEvent) string {
	sevInt := 1
	switch strings.ToUpper(evt.Severity) {
	case "LOW":
		sevInt = 3
	case "MEDIUM":
		sevInt = 5
	case "HIGH":
		sevInt = 8
	case "CRITICAL":
		sevInt = 10
	}

	escapedReason := strings.ReplaceAll(evt.Reason, "|", "\\|")
	return fmt.Sprintf("CEF:0|BAP|ControlPlane|1.1.3|%s|%s|%d|suser=%s duser=%s cs1=%s cs1Label=SessionID cs2=%s cs2Label=TaskID cs3=%s cs3Label=TraceID act=%s res=%s outcome=%s msg=%s",
		evt.EventType,
		evt.EventType,
		sevInt,
		evt.Principal,
		evt.AgentID,
		evt.SessionID,
		evt.TaskID,
		evt.TraceID,
		evt.Action,
		evt.Resource,
		evt.Decision,
		escapedReason,
	)
}

// FormatSyslogRFC5424 formats the security event into standard RFC 5424 Syslog wire format.
func FormatSyslogRFC5424(evt SIEMEvent, hostname string) string {
	if hostname == "" {
		hostname = "bap-controlplane"
	}
	pri := 134 // Facility local0 (16*8) + Severity Info (6) = 134
	if evt.Severity == "CRITICAL" || evt.Severity == "HIGH" {
		pri = 131 // local0 + Error (3) = 131
	}

	ts := evt.Timestamp.Format(time.RFC3339)
	return fmt.Sprintf("<%d>1 %s %s bap-controlplane - %s [bap@7712 session_id=\"%s\" agent_id=\"%s\" task_id=\"%s\" decision=\"%s\" policy_ver=\"%s\"] %s: %s",
		pri,
		ts,
		hostname,
		evt.EventType,
		evt.SessionID,
		evt.AgentID,
		evt.TaskID,
		evt.Decision,
		evt.PolicyVer,
		evt.Action,
		evt.Reason,
	)
}

// ExportAllAsCEF returns all buffered security events formatted as CEF strings.
func (e *SIEMExporter) ExportAllAsCEF() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := make([]string, len(e.events))
	for i, evt := range e.events {
		res[i] = FormatCEF(evt)
	}
	return res
}

// ExportJSON returns all buffered events as JSON.
func (e *SIEMExporter) ExportJSON() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return json.Marshal(e.events)
}
