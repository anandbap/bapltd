package learn

import (
	"fmt"
	"net"
	"sort"
	"strconv"
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
	Humans   int    `json:"humans"`
	Replay   Replay `json:"replay"`
}

// Replay is the proposal run against recorded history: how much friction it removes and whether it would
// have opened anything that must stay closed.
type Replay struct {
	WouldAllow int      `json:"would_allow"` // past denied events this proposal would have allowed
	Unsafe     []string `json:"unsafe,omitempty"`
}

// Mine recommends only exact hosts backed by two distinct, attributed human
// decisions. The caller must supply events from an authenticated approval
// producer, scoped to one project. Agent retries alone never qualify.
func Mine(events []Event, current capability.Profile) []Proposal {
	type agg struct {
		n             int
		sessions      map[string]bool
		humans        map[string]bool
		contributions map[string]bool
		decisions map[string]bool
	}
	byHost := map[string]*agg{}
	for _, e := range events {
		if e.Kind != "egress" || (e.Verdict != "deny" && !e.HumanApproved) {
			continue
		}
		host := hostOf(e.Target)
		port := portOf(e.Target)
		portNumber, portErr := strconv.Atoi(port)
		if host == "" || portErr != nil || portNumber < 1 || portNumber > 65535 {
			continue
		}
		destination := net.JoinHostPort(host, port)
		a := byHost[destination]
		if a == nil {
			a = &agg{sessions: map[string]bool{}, humans: map[string]bool{}, contributions: map[string]bool{}, decisions: map[string]bool{}}
			byHost[destination] = a
		}
		// Retrying or inventing sessions is never human evidence. One agent/session
		// contributes at most one denial to the ranking, regardless of retry count.
		key := e.Agent + "\x00" + e.Session
		if e.Agent != "" { key = e.Agent }
		if e.Verdict == "deny" && !a.contributions[key] {
			a.n++
			a.contributions[key] = true
		}
		if e.Session != "" {
			a.sessions[e.Session] = true
		}
		if e.HumanApproved && e.HumanID != "" && e.DecisionID != "" && !a.decisions[e.DecisionID] && (e.Source == "approval-service" || e.Source == "bap-egress-allow") {
			a.humans[e.HumanID] = true
			a.decisions[e.DecisionID] = true
		}
	}
	var out []Proposal
	for destination, a := range byHost {
		host, port := hostOf(destination), portOf(destination)
		if capability.IsImmutableDenyHost(host) || isIP(host) {
			continue // never proposed: not even as a suggestion
		}
		if capability.MatchEgress(current.EgressAllow, host, port) {
			continue
		}
		if len(a.humans) < 2 {
			continue
		}
		risk := "review"
		reason := fmt.Sprintf("agent was blocked %d time(s) across %d session(s) reaching %s", a.n, len(a.sessions), host)
		if len(a.humans) >= 2 {
			risk = "low"
			reason = fmt.Sprintf("%d distinct humans approved %s; %d capped blocked contribution(s) observed", len(a.humans), host, a.n)
		}
		p := Proposal{Kind: "allow-egress", Value: destination, Evidence: a.n, Sessions: len(a.sessions), Human: true, Humans: len(a.humans), Risk: risk, Reason: reason}
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
	if strings.ContainsAny(p.Value, "*/\\?#@") || isIP(hostOf(p.Value)) {
		return current, fmt.Errorf("learning can only add exact DNS destinations, never wildcards or raw addresses")
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
