package learn

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/capability"
)

func TestAgentCannotManufactureApprovalEvidence(t *testing.T) {
	var events []Event
	for i := 0; i < 500; i++ {
		events = append(events, Event{Kind: "egress", Target: "exfil.example:443", Verdict: "deny", Session: fmt.Sprint(i), Agent: "attacker", HumanApproved: true})
	}
	if got := Mine(events, capability.New(t.TempDir())); len(got) != 0 {
		t.Fatalf("agent activity produced proposals: %+v", got)
	}
	for i := range events {
		events[i].Source = "hook"
		events[i].HumanID = fmt.Sprint(i)
		events[i].DecisionID = fmt.Sprint(i)
	}
	if got := Mine(events, capability.New(t.TempDir())); len(got) != 0 {
		t.Fatal("hook supplied human claims became evidence")
	}
}

func TestNormalizeDecisionPreservesScopeWithoutInventingObservation(t *testing.T) {
	e, ok := NormalizeDecision(Decision{ID: "e", Agent: "a", Project: "p", Session: "s", Source: "broker", Action: "fs:read", Resource: "file:///project/a", Verdict: "allow", Grant: "g"})
	if !ok || e.Kind != "fs" || e.Mode != "read" || e.Target != "file:///project/a" || e.Observed || e.Grant != "g" {
		t.Fatalf("projection: %+v %v", e, ok)
	}
	if _, ok := NormalizeDecision(Decision{Action: "unknown", Resource: "r", Project: "p"}); ok {
		t.Fatal("unknown text was classified as an effect")
	}
}

func TestSingleHumanRetriesAreCapped(t *testing.T) {
	events := []Event{}
	for i := 0; i < 500; i++ {
		e := deny("registry.example", "alice", true)
		events = append(events, e)
	}
	cur := capability.New(t.TempDir())
	if len(Mine(events, cur)) != 0 {
		t.Fatal("one human is not distinct-human evidence")
	}
	events = append(events, deny("registry.example", "bob", true))
	got := Mine(events, cur)
	if len(got) != 1 || got[0].Evidence != 2 || got[0].Humans != 2 {
		t.Fatalf("evidence not capped: %+v", got)
	}
}

func TestPredictionAuditorRequiresCompletedCorrelatedTrace(t *testing.T) {
	events := []Event{}
	targets := []string{"quoted &&", "/", ".bap/relative", "git ls-files", "platform"}
	for i, target := range targets {
		id := fmt.Sprint(i)
		events = append(events, Event{Project: "p", Session: "s", PredictionID: id, Kind: "fs", Mode: "read", Target: target, Verdict: "deny", Source: "hook"})
	}
	if len(PredictionMismatches(events)) != 0 {
		t.Fatal("missing observation is not a false positive")
	}
	for i := range targets {
		events = append(events, Event{Project: "p", Session: "s", PredictionID: fmt.Sprint(i), Kind: "trace-complete", Observed: true, Source: "sandbox"})
	}
	if got := PredictionMismatches(events); len(got) != 5 {
		t.Fatalf("want five candidates, got %+v", got)
	}
	events = append(events, Event{Project: "p", Session: "s", PredictionID: "0", Kind: "fs", Mode: "read", Target: targets[0], Observed: true, Source: "sandbox"})
	if len(PredictionMismatches(events)) != 4 {
		t.Fatal("observed effect was called false positive")
	}
}

func TestComplainPromotionNeedsCleanObservedSoak(t *testing.T) {
	now := time.Now().UTC()
	rule := RuleScope{Rule: "r", Project: "p", Mode: "complain", Since: now.Add(-2 * time.Hour)}
	if allow, would := rule.Evaluate(true); !allow || !would {
		t.Fatal("complain blocked")
	}
	immutable := rule
	immutable.Immutable = true
	if allow, _ := immutable.Evaluate(true); allow {
		t.Fatal("immutable deny weakened")
	}
	if _, err := rule.Promote(nil, now, time.Hour); err == nil {
		t.Fatal("empty soak promoted")
	}
	events := []Event{{Time: now.Add(-time.Minute), Rule: "r", Project: "p", Verdict: "allow"}}
	promoted, err := rule.Promote(events, now, time.Hour)
	if err != nil || promoted.Mode != "enforce" {
		t.Fatalf("clean soak: %+v %v", promoted, err)
	}
	events[0].WouldDeny = true
	if _, err := rule.Promote(events, now, time.Hour); err == nil {
		t.Fatal("friction promoted")
	}
	if _, err := rule.Promote(events, now, 3*time.Hour); err == nil {
		t.Fatal("short soak promoted")
	}
	events[0].Project = "other"
	if _, err := rule.Promote(events, now, time.Hour); err == nil {
		t.Fatal("another project established evidence")
	}
}

func TestTwentyEffectsRoundTripAndPrivateTargets(t *testing.T) {
	log := NewLog(filepath.Join(t.TempDir(), "effects.jsonl"))
	for i := 0; i < 20; i++ {
		target, err := PrivateTarget(fmt.Sprintf("/project/%d", i), []byte(strings.Repeat("a", 32)))
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Append(Event{ID: fmt.Sprint(i), Project: "p", Agent: "a", Session: "s", Kind: "fs", Mode: "read", Target: target, Verdict: "allow", Observed: true}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := log.ReadAll()
	if err != nil || len(events) != 20 {
		t.Fatalf("round trip: %d %v", len(events), err)
	}
	if metrics := Summarize(events); metrics.Events != 20 || metrics.Sessions != 1 || metrics.Denials != 0 {
		t.Fatalf("metrics: %+v", metrics)
	}
	a, _ := PrivateTarget("x", []byte(strings.Repeat("a", 32)))
	b, _ := PrivateTarget("x", []byte(strings.Repeat("b", 32)))
	if a == b {
		t.Fatal("tenant keys did not isolate target hashes")
	}
	if _, err := PrivateTarget("x", nil); err == nil {
		t.Fatal("weak key accepted")
	}
}
