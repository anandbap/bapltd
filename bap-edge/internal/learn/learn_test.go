package learn

import (
	"path/filepath"
	"testing"

	"bap-edge/internal/capability"
)

func deny(host, session string, human bool) Event {
	return Event{Kind: "egress", Target: host + ":443", Verdict: "deny", Session: session, HumanApproved: human}
}

func TestLogRoundTripSkipsCorruptLines(t *testing.T) {
	l := NewLog(filepath.Join(t.TempDir(), "effects.jsonl"))
	if ev, err := l.ReadAll(); err != nil || len(ev) != 0 {
		t.Fatalf("missing log = empty history: %v %v", ev, err)
	}
	_ = l.Append(deny("a.com", "s1", false))
	_ = l.Append(deny("b.com", "s1", false))
	ev, err := l.ReadAll()
	if err != nil || len(ev) != 2 || ev[0].Time.IsZero() {
		t.Fatalf("got %v %v", ev, err)
	}
}

func TestMineNeedsBreadthForAgentOnlyEvidence(t *testing.T) {
	cur := capability.New(t.TempDir())
	// One noisy session hammering a host is not proof it is wanted.
	var evs []Event
	for i := 0; i < 20; i++ {
		evs = append(evs, deny("sketchy.example", "s1", false))
	}
	if ps := Mine(evs, cur); len(ps) != 0 {
		t.Errorf("single-session noise must not become a proposal: %+v", ps)
	}
	// Repeated across sessions it becomes a REVIEW proposal, not a low-risk one.
	evs = append(evs, deny("registry.npmjs.org", "s1", false), deny("registry.npmjs.org", "s2", false), deny("registry.npmjs.org", "s3", false))
	ps := Mine(evs, cur)
	if len(ps) != 1 || ps[0].Value != "registry.npmjs.org" || ps[0].Risk != "review" || ps[0].Replay.WouldAllow != 3 {
		t.Fatalf("got %+v", ps)
	}
}

func TestHumanApprovedEvidenceIsStrongAndRanksFirst(t *testing.T) {
	cur := capability.New(t.TempDir())
	evs := []Event{deny("github.com", "s1", true), deny("a.com", "s1", false), deny("a.com", "s2", false), deny("a.com", "s3", false)}
	ps := Mine(evs, cur)
	if len(ps) != 2 || ps[0].Value != "github.com" || ps[0].Risk != "low" || !ps[0].Human {
		t.Fatalf("got %+v", ps)
	}
}

func TestImmutableAndRawIPTargetsAreNeverProposed(t *testing.T) {
	cur := capability.New(t.TempDir())
	var evs []Event
	for i := 0; i < 10; i++ {
		evs = append(evs, deny("169.254.169.254", "s1", true), deny("169.254.169.254", "s2", true), deny("203.0.113.9", "s1", true), deny("203.0.113.9", "s2", true))
	}
	if ps := Mine(evs, cur); len(ps) != 0 {
		t.Errorf("metadata and raw IP exfil targets must never be suggested, even with human-flagged events: %+v", ps)
	}
}

func TestAlreadyAllowedHostsAreNotReproposedAndApplyWorks(t *testing.T) {
	cur, _ := capability.New(t.TempDir()).AddEgress("*.pypi.org")
	evs := []Event{deny("files.pypi.org", "s1", true), deny("crates.io", "s1", true)}
	ps := Mine(evs, cur)
	if len(ps) != 1 || ps[0].Value != "crates.io" {
		t.Fatalf("got %+v", ps)
	}
	next, err := Apply(ps[0], cur)
	if err != nil || !capability.MatchEgress(next.EgressAllow, "crates.io", "443") {
		t.Fatalf("apply: %+v %v", next, err)
	}
	if _, err := Apply(Proposal{Kind: "allow-egress", Value: "169.254.169.254"}, cur); err == nil {
		t.Error("apply must refuse an immutable target even if a proposal were forged")
	}
	if _, err := Apply(Proposal{Kind: "allow-egress", Value: "x.com", Replay: Replay{Unsafe: []string{"y"}}}, cur); err == nil {
		t.Error("a proposal that failed replay safety must not apply")
	}
}
