package audit

import "testing"

func TestEvidenceGradeBoundToChainAndLegacyUnchanged(t *testing.T) {
	s := NewStore()
	_, err := s.Ingest([]Event{
		{EventID: "legacy", SessionID: "a", Decision: "allow"},
		{EventID: "layer", SessionID: "a", ReportingLayer: "hook", Decision: "allow"},
		{EventID: "graded", SessionID: "a", ReportingLayer: "mcp", EvidenceGrade: "self_reported", TurnID: "t1", Decision: "observed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := s.List(0)
	if got[0].HashVersion != 2 || got[1].HashVersion != 3 || got[2].HashVersion != 4 {
		t.Fatalf("unexpected hash versions: %d %d %d", got[0].HashVersion, got[1].HashVersion, got[2].HashVersion)
	}
	if ok, err := s.VerifyChain(); !ok {
		t.Fatalf("chain should verify: %v", err)
	}
	s.events[2].EvidenceGrade = "verified"
	if ok, _ := s.VerifyChain(); ok {
		t.Fatal("changing evidence grade must break the chain")
	}
}
