package api

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"bap-controlplane/internal/audit"
)

// BAP-931: one logical agent action is logged by several layers (native tool hook, PowerShell wrapper
// hook, broker), and a denied `bapedge zsp authorize` is logged both as the control command and as a
// denial. Counting raw events made the totals wrong (an action counted 2-6 times, a refusal counted as
// "allowed", every grant USE counted as a MINT). summarizeSessionCalls collapses events into distinct
// logical actions with one outcome each and counts those.

const (
	outcomeAllowed        = "allowed"
	outcomeAllowedLimited = "allowed_limited"
	outcomeBlocked        = "blocked"
	outcomeFailed         = "failed" // allowed by policy, but the command itself exited non-zero
	outcomeUnclassified   = "unclassified"
)

func isAllowDecision(d string) bool {
	d = strings.ToLower(strings.TrimSpace(d))
	return strings.HasPrefix(d, "allow") || d == "approve" || d == "approved" || d == "granted" || d == "ok" || d == "enrolled" || d == "restored"
}

// callGroupWindow is how far apart events of the same logical action may be.
const callGroupWindow = 20 * time.Second

// CallRecord is one distinct logical action.
type CallRecord struct {
	Timestamp         string   `json:"timestamp"`
	Action            string   `json:"action"`
	Decision          string   `json:"decision"` // ALLOWED | ALLOWED-LIMITED | BLOCKED
	Outcome           string   `json:"outcome"`  // allowed | allowed_limited | blocked | failed
	Reason            string   `json:"reason,omitempty"`
	ExitCode          int      `json:"exit_code,omitempty"`
	GrantID           string   `json:"grant_id,omitempty"`
	CanonicalResource string   `json:"canonical_resource,omitempty"`
	NarrowingApplied  bool     `json:"narrowing_applied,omitempty"`
	NarrowingReason   string   `json:"narrowing_reason,omitempty"`
	RequestedActions  []string `json:"requested_actions,omitempty"`
	AllowedActions    []string `json:"allowed_actions,omitempty"`
	ZSPConcept        string   `json:"zsp_concept,omitempty"`
	Layers            []string `json:"layers,omitempty"`
	EventCount        int      `json:"event_count"`
}

// CallsSummary is the corrected, de-duplicated view of a session.
type CallsSummary struct {
	Calls          []CallRecord
	TotalActions   int
	Allowed        int // executed under policy and exited cleanly
	AllowedLimited int // granted, but narrowed (ALLOWED-LIMITED)
	Blocked        int
	Failed         int // allowed by policy but exited non-zero (counted here, not in Allowed)
	Unclassified   int // decision value BAP does not recognize (never counted as allowed)
	RawEvents      int
	Concepts       map[string]int
}

var authorizeActionsRe = regexp.MustCompile(`--actions[ =]+"?([^"\s]+)`)

func isAuthorizeCommand(cmd string) bool {
	return strings.Contains(strings.ToLower(cmd), "zsp authorize")
}

// callKey normalizes a command so the same logical action matches across layers and so an authorize
// attempt matches its denial record.
func callKey(cmd string) string {
	low := strings.ToLower(strings.Join(strings.Fields(cmd), " "))
	if isAuthorizeCommand(low) {
		if m := authorizeActionsRe.FindStringSubmatch(low); m != nil {
			return "zsp-authorize:" + m[1]
		}
		return "zsp-authorize"
	}
	return low
}

func isDenyDecision(d string) bool {
	d = strings.ToLower(d)
	return strings.Contains(d, "deny") || strings.Contains(d, "denied") || strings.Contains(d, "block") || strings.Contains(d, "forbid")
}

func isLimitedEvent(e audit.Event) bool {
	d := strings.ToLower(e.Decision)
	return e.NarrowingApplied || strings.Contains(d, "limit") || strings.Contains(d, "narrow")
}

func isFailedExec(e audit.Event) bool {
	r := strings.ToLower(e.Reason)
	return strings.Contains(r, "command execution failed") || (e.ExitCode != 0 && !isDenyDecision(e.Decision))
}

func conceptFromReason(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "max uses exceeded") || strings.Contains(r, "already burned"):
		return "ZSP_SINGLE_USE_BURN"
	case strings.Contains(r, "wildcard permission is not permitted"):
		return "ZSP_WILDCARD_REJECTED"
	case strings.Contains(r, "never grantable") || strings.Contains(r, "permission policy denies"):
		return "ZSP_HARD_DENY"
	case strings.Contains(r, "mint cap"):
		return "ZSP_MINT_CAP"
	case strings.Contains(r, "zero standing privilege") || strings.Contains(r, "zerostandingprivilege"):
		return "ZSP_DENY_NO_GRANT"
	case strings.Contains(r, "credential") || strings.Contains(r, ".env"):
		return "CREDENTIAL_ISOLATION"
	case strings.Contains(r, "out-of-band") || strings.Contains(r, "high-risk"):
		return "HIGH_RISK_OOB_GATE"
	}
	return ""
}

type callGroup struct {
	key    string
	last   time.Time
	events []audit.Event
}

func parseEventTime(ts string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t
		}
	}
	return time.Time{}
}

func isConversationEvent(e audit.Event) bool {
	return e.FullCommand == "USER_PROMPT_SUBMITTED" || e.FullCommand == "AGENT_RESPONSE" || e.Executable == "agent_response"
}

// summarizeSessionCalls groups raw audit events into distinct logical actions and counts them.
func summarizeSessionCalls(events []audit.Event) CallsSummary {
	sum := CallsSummary{Concepts: map[string]int{}}

	acts := make([]audit.Event, 0, len(events))
	for _, e := range events {
		if isConversationEvent(e) {
			continue
		}
		acts = append(acts, e)
	}
	sum.RawEvents = len(acts)
	sort.SliceStable(acts, func(i, j int) bool {
		return parseEventTime(acts[i].Timestamp).Before(parseEventTime(acts[j].Timestamp))
	})

	var groups []*callGroup
	for _, e := range acts {
		ts := parseEventTime(e.Timestamp)
		key := callKey(e.FullCommand)
		var target *callGroup
		for i := len(groups) - 1; i >= 0; i-- {
			g := groups[i]
			if g.key == key && ts.Sub(g.last) <= callGroupWindow {
				target = g
				break
			}
			if ts.Sub(g.last) > callGroupWindow*3 {
				break
			}
		}
		if target == nil {
			target = &callGroup{key: key}
			groups = append(groups, target)
		}
		target.events = append(target.events, e)
		if ts.After(target.last) {
			target.last = ts
		}
	}

	for _, g := range groups {
		rec := resolveGroup(g)
		sum.Calls = append(sum.Calls, rec)
		switch rec.Outcome {
		case outcomeBlocked:
			sum.Blocked++
		case outcomeAllowedLimited:
			sum.AllowedLimited++
		case outcomeFailed:
			sum.Failed++
		case outcomeUnclassified:
			sum.Unclassified++
		default:
			sum.Allowed++
		}
		if rec.ZSPConcept != "" {
			sum.Concepts[rec.ZSPConcept]++
		}
	}
	sum.TotalActions = len(sum.Calls)
	return sum
}

// Partition splits the distinct actions into allowed (clean and failed-exec), blocked and allowed-limited lists.
func (s CallsSummary) Partition() (allowed, blocked, limited []CallRecord) {
	allowed, blocked, limited = []CallRecord{}, []CallRecord{}, []CallRecord{}
	for _, c := range s.Calls {
		switch c.Outcome {
		case outcomeBlocked:
			blocked = append(blocked, c)
		case outcomeAllowedLimited:
			limited = append(limited, c)
		case outcomeAllowed, outcomeFailed:
			allowed = append(allowed, c)
		}
	}
	return allowed, blocked, limited
}

func resolveGroup(g *callGroup) CallRecord {
	var deny, limited, failed *audit.Event
	layers := map[string]bool{}
	rep := &g.events[len(g.events)-1]
	for i := range g.events {
		e := &g.events[i]
		if e.ReportingLayer != "" {
			layers[e.ReportingLayer] = true
		}
		switch {
		case isDenyDecision(e.Decision):
			// Prefer the most specific refusal (longest reason).
			if deny == nil || len(e.Reason) > len(deny.Reason) {
				deny = e
			}
		case isLimitedEvent(*e):
			limited = e
		case isFailedExec(*e):
			failed = e
		}
		if e.GrantID != "" && rep.GrantID == "" {
			rep = e
		}
	}

	outcome := outcomeAllowed
	switch {
	case deny != nil:
		outcome, rep = outcomeBlocked, deny
	case limited != nil:
		outcome, rep = outcomeAllowedLimited, limited
	case failed != nil:
		outcome, rep = outcomeFailed, failed
	case !isAllowDecision(rep.Decision):
		// Never let an unrecognized decision (ERROR, UNKNOWN, ...) inflate the allowed count.
		outcome = outcomeUnclassified
	}

	decision := "ALLOWED"
	switch outcome {
	case outcomeBlocked:
		decision = "BLOCKED"
	case outcomeAllowedLimited:
		decision = "ALLOWED-LIMITED"
	}

	concept := rep.ZSPConcept
	if concept == "" {
		concept = conceptFromReason(rep.Reason)
	}
	if concept == "" {
		for i := range g.events {
			if g.events[i].ZSPConcept != "" {
				concept = g.events[i].ZSPConcept
				break
			}
		}
	}
	// A grant USE is not a grant MINT: only the authorize command mints.
	if concept == "ZSP_GRANT_MINTED" && !isAuthorizeCommand(rep.FullCommand) {
		concept = "ZSP_GRANT_USED"
	}
	if concept == "" && outcome == outcomeAllowed && isAuthorizeCommand(rep.FullCommand) && rep.GrantID != "" {
		concept = "ZSP_GRANT_MINTED"
	}
	if outcome == outcomeAllowedLimited && (concept == "" || concept == "ZSP_GRANT_MINTED") {
		concept = "ZSP_SCOPE_NARROWED"
	}

	layerList := make([]string, 0, len(layers))
	for l := range layers {
		layerList = append(layerList, l)
	}
	sort.Strings(layerList)

	return CallRecord{
		Timestamp:         rep.Timestamp,
		Action:            rep.FullCommand,
		Decision:          decision,
		Outcome:           outcome,
		Reason:            rep.Reason,
		ExitCode:          rep.ExitCode,
		GrantID:           rep.GrantID,
		CanonicalResource: rep.CanonicalResource,
		NarrowingApplied:  rep.NarrowingApplied || outcome == outcomeAllowedLimited,
		NarrowingReason:   rep.NarrowingReason,
		RequestedActions:  rep.RequestedActions,
		AllowedActions:    rep.AllowedActions,
		ZSPConcept:        concept,
		Layers:            layerList,
		EventCount:        len(g.events),
	}
}
