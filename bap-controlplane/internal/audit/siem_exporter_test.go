package audit

import (
	"strings"
	"testing"
	"time"
)

func TestSIEMExporter_FormatCEFAndSyslog(t *testing.T) {
	exp := NewSIEMExporter("")

	evt := SIEMEvent{
		EventID:   "evt-101",
		Timestamp: time.Now().UTC(),
		Severity:  "CRITICAL",
		EventType: "CANARY_TRIPPED",
		AgentID:   "agent-finance-01",
		SessionID: "sess-99",
		TaskID:    "task-audit",
		Principal: "user:developer",
		Action:    "read_file",
		Resource:  ".bap_canary_token",
		Decision:  "DENY",
		Reason:    "Honeytoken canary tripwire tripped",
		PolicyVer: "v1.1.3",
		TraceID:   "trace-abc",
	}

	exp.RecordEvent(evt)

	// 1. CEF formatting test
	cef := FormatCEF(evt)
	if !strings.HasPrefix(cef, "CEF:0|BAP|ControlPlane|1.1.3|CANARY_TRIPPED|CANARY_TRIPPED|10|") {
		t.Fatalf("unexpected CEF header: %s", cef)
	}
	if !strings.Contains(cef, "act=read_file") || !strings.Contains(cef, "res=.bap_canary_token") || !strings.Contains(cef, "outcome=DENY") {
		t.Fatalf("missing required CEF fields: %s", cef)
	}

	// 2. Syslog RFC 5424 formatting test
	syslog := FormatSyslogRFC5424(evt, "controlplane.corp.internal")
	if !strings.HasPrefix(syslog, "<131>1 ") { // priority 131 for CRITICAL
		t.Fatalf("unexpected Syslog priority: %s", syslog)
	}
	if !strings.Contains(syslog, "bap@7712") || !strings.Contains(syslog, "agent_id=\"agent-finance-01\"") {
		t.Fatalf("missing structured Syslog data: %s", syslog)
	}

	// 3. Export all as CEF
	cefList := exp.ExportAllAsCEF()
	if len(cefList) != 1 {
		t.Fatalf("expected 1 exported CEF event, got %d", len(cefList))
	}
}
