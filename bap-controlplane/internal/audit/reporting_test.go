package audit

import "testing"

func TestReportingLayerBoundToAuditChain(t *testing.T) {
	s := NewStore()
	if _, err := s.Ingest([]Event{{EventID: "layer-v3", SessionID: "codex", ReportingLayer: "discovery", Decision: "observed"}}); err != nil {
		t.Fatal(err)
	}
	if s.events[0].HashVersion != 3 {
		t.Fatal("reporting evidence must use version 3")
	}
	if valid, err := s.VerifyChain(); !valid || err != nil {
		t.Fatal(err)
	}
	s.events[0].ReportingLayer = "broker"
	if valid, _ := s.VerifyChain(); valid {
		t.Fatal("tampered coverage still verifies")
	}
}
