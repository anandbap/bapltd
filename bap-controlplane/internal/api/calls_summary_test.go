package api

import (
	"fmt"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
)

// BAP-931 regression: the shape of a real session (hook + PowerShell wrapper + broker per action, a denied
// authorize logged twice, grant uses tagged as mints) must summarize to distinct, correct counts.

var base = time.Date(2026, 11, 12, 22, 27, 50, 0, time.UTC)

func ev(offsetSec int, layer, cmd, decision, reason string, mut func(*audit.Event)) audit.Event {
	e := audit.Event{
		Timestamp:      base.Add(time.Duration(offsetSec) * time.Second).Format(time.RFC3339Nano),
		ReportingLayer: layer,
		Executable:     "x",
		FullCommand:    cmd,
		Decision:       decision,
		Reason:         reason,
	}
	if mut != nil {
		mut(&e)
	}
	return e
}

func sessionEvents() []audit.Event {
	var evs []audit.Event
	// 1. authorize (mint): 2 hook + 2 broker events, one with the mint reason.
	auth := `bapedge zsp authorize --session-id "s" --goal "g" --actions "git:status,git:log" --resources workspace://current`
	evs = append(evs,
		ev(0, "hook", auth, "allow", "", nil),
		ev(1, "hook", auth, "allow", "", nil),
		ev(3, "broker", "bapedge zsp authorize --actions git:status,git:log", "allow", "TaskGrant g1 minted", func(e *audit.Event) { e.GrantID = "g1"; e.ZSPConcept = "ZSP_GRANT_MINTED" }),
		ev(4, "broker", auth, "allow", "", nil),
	)
	// 2. git status: hook x2 (tool + wrapper) + broker exit 1. Uses of g1 are tagged MINTED by the edge.
	for _, off := range []int{10, 11} {
		evs = append(evs, ev(off, "hook", "git status", "allow", "", func(e *audit.Event) { e.GrantID = "g1"; e.ZSPConcept = "ZSP_GRANT_MINTED" }))
	}
	evs = append(evs, ev(13, "broker", "git status", "allow", "Command execution failed: exit status 1", func(e *audit.Event) { e.GrantID = "g1"; e.ExitCode = 1 }))
	// 3. A clean allowed command (hook x2 + broker ok).
	for _, off := range []int{20, 21} {
		evs = append(evs, ev(off, "hook", "git log -n 5", "allow", "", func(e *audit.Event) { e.GrantID = "g1" }))
	}
	evs = append(evs, ev(23, "broker", "git log -n 5", "allow", "", func(e *audit.Event) { e.GrantID = "g1" }))
	// 4. Rejected wildcard authorize: hook allows the control command, broker says exit 1, and a denial event is recorded.
	wild := `bapedge zsp authorize --session-id "s" --actions "cli:*" --resources workspace://current`
	evs = append(evs,
		ev(30, "hook", wild, "allow", "", nil),
		ev(31, "hook", wild, "allow", "", nil),
		ev(33, "broker", wild, "allow", "Command execution failed: exit status 1", nil),
		ev(33, "hook", "bapedge zsp authorize --actions cli:*", "deny", "wildcard permission is not permitted: \"cli:*\"", func(e *audit.Event) { e.ZSPConcept = "ZSP_WILDCARD_REJECTED" }),
	)
	// 5. Burn: the same denial logged by 8 layers/wrappers.
	for i := 0; i < 8; i++ {
		evs = append(evs, ev(40+i/4, "hook", "git status --short", "deny", "ZeroStandingPrivilegeViolation: task grant already burned (max uses exceeded)", nil))
	}
	// 6. Narrowed grant: one ALLOWED-LIMITED mint (+ its control-command echoes).
	broad := `bapedge zsp authorize --session-id "s" --actions "repo:*,fs:*" --resources repo:*`
	evs = append(evs,
		ev(60, "hook", broad, "allow", "", nil),
		ev(63, "broker", "bapedge zsp authorize --actions repo:*,fs:*", "ALLOWED-LIMITED", "Monotonic scope attenuation", func(e *audit.Event) {
			e.NarrowingApplied = true
			e.GrantID = "g2"
			e.RequestedActions = []string{"repo:*", "fs:*"}
			e.AllowedActions = []string{"repo:read", "fs:read"}
			e.ZSPConcept = "ZSP_SCOPE_NARROWED"
		}),
	)
	// 7. Credential isolation: one command, 6 duplicates.
	for i := 0; i < 6; i++ {
		evs = append(evs, ev(70, "hook", "bapedge zsp authorize --goal read .env", "deny", "Security Invariant Violation: Direct access to sensitive credential store is strictly forbidden", nil))
	}
	// A prompt and a reply are not actions.
	evs = append(evs, audit.Event{Timestamp: base.Format(time.RFC3339), FullCommand: "USER_PROMPT_SUBMITTED"}, audit.Event{Timestamp: base.Format(time.RFC3339), FullCommand: "AGENT_RESPONSE"})
	return evs
}

func TestBAP931_CallsAreDeduplicatedAndClassified(t *testing.T) {
	sum := summarizeSessionCalls(sessionEvents())

	// Distinct actions: mint, git status (failed), git log, wildcard authorize (blocked), burn (blocked),
	// narrowed mint, credential block = 7.
	if sum.TotalActions != 7 {
		for _, c := range sum.Calls {
			t.Logf("%-16s %-8s %s", c.Outcome, c.ZSPConcept, c.Action)
		}
		t.Fatalf("expected 7 distinct actions, got %d (raw events %d)", sum.TotalActions, sum.RawEvents)
	}
	if sum.RawEvents < 25 {
		t.Fatalf("test data should be noisy, raw=%d", sum.RawEvents)
	}
	if sum.Allowed != 2 || sum.Failed != 1 || sum.AllowedLimited != 1 || sum.Blocked != 3 {
		t.Fatalf("allowed=%d failed=%d limited=%d blocked=%d (want 2/1/1/3)", sum.Allowed, sum.Failed, sum.AllowedLimited, sum.Blocked)
	}
	if sum.Allowed+sum.Failed+sum.AllowedLimited+sum.Blocked+sum.Unclassified != sum.TotalActions {
		t.Fatal("outcome counts must sum to the number of distinct actions")
	}

	// Concepts count distinct actions, not events; a grant USE is not a MINT.
	want := map[string]int{
		"ZSP_GRANT_MINTED":      1,
		"ZSP_GRANT_USED":        1, // git status
		"ZSP_WILDCARD_REJECTED": 1,
		"ZSP_SINGLE_USE_BURN":   1,
		"ZSP_SCOPE_NARROWED":    1,
		"CREDENTIAL_ISOLATION":  1,
	}
	for k, v := range want {
		if sum.Concepts[k] != v {
			t.Errorf("concept %s = %d, want %d (all: %v)", k, sum.Concepts[k], v, sum.Concepts)
		}
	}
}

func TestBAP931_RejectedAuthorizeIsBlockedNotAllowed(t *testing.T) {
	sum := summarizeSessionCalls(sessionEvents())
	for _, c := range sum.Calls {
		if c.Outcome == outcomeBlocked && c.ZSPConcept == "ZSP_WILDCARD_REJECTED" {
			if c.Decision != "BLOCKED" || c.Reason == "" {
				t.Fatalf("wildcard rejection must be BLOCKED with the real reason, got %+v", c)
			}
			return
		}
	}
	t.Fatal("wildcard rejection not reported as a blocked action")
}

func TestBAP931_AllowedLimitedIsDistinctAndNotDoubleCounted(t *testing.T) {
	sum := summarizeSessionCalls(sessionEvents())
	var lim *CallRecord
	for i := range sum.Calls {
		if sum.Calls[i].Outcome == outcomeAllowedLimited {
			lim = &sum.Calls[i]
		}
	}
	if lim == nil {
		t.Fatal("ALLOWED-LIMITED action missing")
	}
	if lim.Decision != "ALLOWED-LIMITED" || !lim.NarrowingApplied || len(lim.RequestedActions) != 2 || len(lim.AllowedActions) != 2 {
		t.Fatalf("limited record must carry requested vs granted: %+v", lim)
	}
	// Not also counted as a plain allowed call.
	if sum.Allowed != 2 {
		t.Fatalf("limited action leaked into allowed count: %d", sum.Allowed)
	}
}

func TestBAP931_UnknownDecisionsAreNotCountedAsAllowed(t *testing.T) {
	evs := []audit.Event{ev(0, "hook", "weird", "ERROR", "boom", nil)}
	sum := summarizeSessionCalls(evs)
	// An unclassified decision is shown, but never silently inflates "allowed"; it is not blocked either.
	if sum.TotalActions != 1 || sum.Allowed != 0 || sum.Blocked != 0 || sum.Unclassified != 1 {
		t.Fatalf("unknown decision must be unclassified only: %+v", sum)
	}
	_ = fmt.Sprint(sum)
}

func TestBAP931_SameCommandFarApartIsTwoActions(t *testing.T) {
	evs := []audit.Event{
		ev(0, "hook", "git status", "allow", "", nil),
		ev(300, "hook", "git status", "allow", "", nil),
	}
	if sum := summarizeSessionCalls(evs); sum.TotalActions != 2 {
		t.Fatalf("two runs minutes apart are two actions, got %d", sum.TotalActions)
	}
}
