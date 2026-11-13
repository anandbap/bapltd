package learn

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"bap-edge/internal/capability"
)

// Proposal is a recommended boundary change with its evidence. It is advice, never an action.
type Proposal struct {
	Kind     string `json:"kind"`     // allow-egress
	Value    string `json:"value"`    // host pattern
	Evidence int    `json:"evidence"` // denied attempts observed
	Sessions int    `json:"sessions"` // distinct sessions that hit it
	Human    bool   `json:"human"`    // a human approved this before
	Risk     string `json:"risk"`     // low | review
	Reason   string `json:"reason"`
	Replay   Replay `json:"replay"`
}

// Replay is the proposal run against recorded history: how much friction it removes and whether it would
// have opened anything that must stay closed.
type Replay struct {
	WouldAllow int      `json:"would_allow"` // past denied events this proposal would have allowed
	Unsafe     []string `json:"unsafe,omitempty"`
}

// Thresholds: an agent repeatedly failing is not proof the access is wanted (it may be exfiltrating), so
// agent-only evidence needs breadth (several sessions) and always lands as "review"; a human approval
// is strong evidence on its own.
const (
	minAgentEvidence = 3
	minAgentSessions = 2
)

// Mine turns denied egress events into proposals, strongest evidence first.
func Mine(events []Event, current capability.Profile) []Proposal {
	type agg struct {
		n        int
		sessions map[string]bool
		human    bool
	}
	byHost := map[string]*agg{}
	for _, e := range events {
		if e.Kind != "egress" || e.Verdict != "deny" {
			continue
		}
		host := hostOf(e.Target)
		if host == "" {
			continue
		}
		a := byHost[host]
		if a == nil {
			a = &agg{sessions: map[string]bool{}}
			byHost[host] = a
		}
		a.n++
		a.sessions[e.Session] = true
		a.human = a.human || e.HumanApproved
	}
	var out []Proposal
	for host, a := range byHost {
		if capability.IsImmutableDenyHost(host) || isIP(host) {
			continue // never proposed: not even as a suggestion
		}
		if capability.MatchEgress(current.EgressAllow, host, "") {
			continue
		}
		if !a.human && (a.n < minAgentEvidence || len(a.sessions) < minAgentSessions) {
			continue
		}
		risk := "review"
		reason := fmt.Sprintf("agent was blocked %d time(s) across %d session(s) reaching %s", a.n, len(a.sessions), host)
		if a.human {
			risk = "low"
			reason = fmt.Sprintf("a human already approved %s; %d blocked attempt(s) observed", host, a.n)
		}
		p := Proposal{Kind: "allow-egress", Value: host, Evidence: a.n, Sessions: len(a.sessions), Human: a.human, Risk: risk, Reason: reason}
		p.Replay = ReplayProposal(p, events, current)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Human != out[j].Human {
			return out[i].Human
		}
		if out[i].Evidence != out[j].Evidence {
			return out[i].Evidence > out[j].Evidence
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// ReplayProposal evaluates p against history with p applied to the current profile.
func ReplayProposal(p Proposal, events []Event, current capability.Profile) Replay {
	next, err := current.AddEgress(p.Value)
	var r Replay
	if err != nil {
		r.Unsafe = append(r.Unsafe, err.Error())
		return r
	}
	for _, e := range events {
		if e.Kind != "egress" {
			continue
		}
		host := hostOf(e.Target)
		port := portOf(e.Target)
		now := capability.MatchEgress(next.EgressAllow, host, port)
		was := capability.MatchEgress(current.EgressAllow, host, port)
		if e.Verdict == "deny" && now && !was {
			r.WouldAllow++
		}
		if now && capability.IsImmutableDenyHost(host) {
			r.Unsafe = append(r.Unsafe, host)
		}
	}
	return r
}

// Apply validates and applies a proposal to a profile. The caller (a human-only CLI path) persists it.
func Apply(p Proposal, current capability.Profile) (capability.Profile, error) {
	if p.Kind != "allow-egress" {
		return current, fmt.Errorf("unsupported proposal kind %q", p.Kind)
	}
	if len(p.Replay.Unsafe) > 0 {
		return current, fmt.Errorf("proposal failed replay safety: %s", strings.Join(p.Replay.Unsafe, ", "))
	}
	return current.AddEgress(p.Value)
}

func hostOf(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return t
}

func portOf(target string) string {
	if _, p, err := net.SplitHostPort(strings.TrimSpace(target)); err == nil {
		return p
	}
	return ""
}

func isIP(h string) bool { return net.ParseIP(strings.Trim(h, "[]")) != nil }
