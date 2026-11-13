package learn

import (
	"strings"
	"time"
)

// Decision is the privacy-limited projection of an existing policy decision.
// It deliberately has no prompt, arguments or full command field. A broker
// decision is not represented as a kernel observation of its filesystem effects.
type Decision struct {
	ID, Agent, Project, Session, Source, Action, Resource, Verdict, Grant string
	Time                                                                  time.Time
}

func NormalizeDecision(d Decision) (Event, bool) {
	if d.Action == "" || d.Resource == "" || d.Project == "" {
		return Event{}, false
	}
	parts := strings.Split(d.Action, ":")
	kind := parts[0]
	switch kind {
	case "fs", "git", "net":
	case "cli", "dev":
		kind = "exec"
	default:
		return Event{}, false
	}
	mode := parts[len(parts)-1]
	outcome := strings.ToLower(d.Verdict)
	switch {
	case strings.HasPrefix(outcome, "allow"):
		outcome = "allow"
	case strings.Contains(outcome, "deny") || strings.Contains(outcome, "denied") || strings.Contains(outcome, "block"):
		outcome = "deny"
	default:
		outcome = "unknown"
	}
	return Event{ID: d.ID, Agent: d.Agent, Project: d.Project, Session: d.Session, Time: d.Time, Source: d.Source, Kind: kind, Mode: mode, Target: d.Resource, Verdict: outcome, Outcome: outcome, Grant: d.Grant}, true
}
