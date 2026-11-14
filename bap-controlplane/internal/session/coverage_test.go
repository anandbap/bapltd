package session

import (
	"reflect"
	"testing"

	"bap-controlplane/internal/audit"
)

const covTS = "2026-11-14T03:00:01Z"

func TestArbitrateHookOutranksMCPForSamePrompt(t *testing.T) {
	in := []audit.Event{
		{SessionID: "s", ReportingLayer: "mcp", EvidenceGrade: GradeSelfReported, Executable: "user_prompt", TurnID: "t1", Timestamp: covTS},
		{SessionID: "s", ReportingLayer: "hook", Executable: "user_prompt", TurnID: "t1", Timestamp: covTS},
	}
	got := Arbitrate(in)
	if len(got) != 1 {
		t.Fatalf("want 1 primary, got %d: %+v", len(got), got)
	}
	if got[0].ReportingLayer != "hook" || got[0].EvidenceGrade != GradeVerified {
		t.Fatalf("hook should be primary and verified: %+v", got[0])
	}
	if !reflect.DeepEqual(got[0].CorroboratingLayers, []string{"mcp"}) {
		t.Fatalf("mcp should corroborate: %+v", got[0].CorroboratingLayers)
	}
}

func TestArbitrateKeepsSelfReportedWhenHookAbsent(t *testing.T) {
	in := []audit.Event{{SessionID: "s", ReportingLayer: "mcp", EvidenceGrade: GradeSelfReported, Executable: "user_prompt", TurnID: "t1", Timestamp: covTS}}
	got := Arbitrate(in)
	if len(got) != 1 || got[0].EvidenceGrade != GradeSelfReported || len(got[0].CorroboratingLayers) != 0 {
		t.Fatalf("self reported prompt must survive unchanged: %+v", got)
	}
}

func TestArbitrateBrokerOutranksShimForSameCommand(t *testing.T) {
	in := []audit.Event{
		{SessionID: "s", ReportingLayer: "shim", FullCommand: "git  status", Executable: "git", Timestamp: covTS},
		{SessionID: "s", ReportingLayer: "broker", FullCommand: "GIT status", Executable: "git", Timestamp: covTS},
	}
	got := Arbitrate(in)
	if len(got) != 1 || got[0].ReportingLayer != "broker" || !reflect.DeepEqual(got[0].CorroboratingLayers, []string{"shim"}) {
		t.Fatalf("broker should be primary with shim support: %+v", got)
	}
}

func TestArbitrateNeverMergesGatewayOrAcrossSessions(t *testing.T) {
	in := []audit.Event{
		{SessionID: "s1", ReportingLayer: "gateway", FullCommand: "curl x", Executable: "curl", Timestamp: covTS},
		{SessionID: "s1", ReportingLayer: "broker", FullCommand: "curl x", Executable: "curl", Timestamp: covTS},
		{SessionID: "s2", ReportingLayer: "broker", FullCommand: "curl x", Executable: "curl", Timestamp: covTS},
	}
	if got := Arbitrate(in); len(got) != 3 {
		t.Fatalf("gateway and other sessions must not merge, got %d", len(got))
	}
}

func TestArbitrateDoesNotModifyInput(t *testing.T) {
	in := []audit.Event{{SessionID: "s", ReportingLayer: "mcp", Executable: "user_prompt", TurnID: "t1", Timestamp: covTS}}
	_ = Arbitrate(in)
	if in[0].EvidenceGrade != "" || in[0].CorroboratingLayers != nil {
		t.Fatalf("input mutated: %+v", in[0])
	}
}

func TestApplyCoverageDegradedReasons(t *testing.T) {
	cases := []struct {
		name   string
		layers []string
		hooks  bool
		reason string
		l1     string
	}{
		{"hooks observed", []string{"hook", "broker"}, false, "", CoverageObserved},
		{"hooks silent lower active", []string{"mcp"}, false, DegradedHooksUnapproved, CoverageSilent},
		{"hooks disabled flag", []string{"broker"}, true, DegradedHooksDisabled, CoverageSilent},
		{"discovery only", []string{"discovery"}, false, DegradedNoEvidence, CoverageSilent},
		{"empty", nil, false, "", CoverageSilent},
	}
	for _, c := range cases {
		s := &Session{ReportingLayers: c.layers, HooksDisabled: c.hooks}
		applyCoverage(s)
		if s.DegradedReason != c.reason || s.Coverage["layer1_hooks"] != c.l1 {
			t.Errorf("%s: reason=%q l1=%q", c.name, s.DegradedReason, s.Coverage["layer1_hooks"])
		}
	}
}
