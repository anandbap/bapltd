package authz

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func writeExpired(dir string, p *PendingApproval) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(approvalPath(dir, p.ID), data, 0600)
}

func raiseFor(t *testing.T, dir, sess string, actions ...string) *PendingApproval {
	t.Helper()
	p, err := RaisePendingApproval(dir, PendingApproval{
		SessionID: sess, ClientType: "claude-code", Mission: "TASK_EXECUTION", Goal: "run a script",
		Actions: actions, Resources: []string{escalationWorkspace}, MaxUses: 3, TTLSeconds: 600,
		Reason: "interpreters need approval",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBAP936_RaiseListDedupeAndApproveMintsTheRequestedGrant(t *testing.T) {
	dir := t.TempDir()
	// The agent is refused...
	if err := mintAs(t, dir, "sess-h", []string{"dev:python:exec"}, []string{escalationWorkspace}); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Fatalf("expected approval requirement, got %v", err)
	}
	// ...so a request is raised; retries do not create duplicates.
	p1 := raiseFor(t, dir, "sess-h", "dev:python:exec")
	p2 := raiseFor(t, dir, "sess-h", "dev:python:exec")
	if p1.ID != p2.ID || p1.Status != "pending" {
		t.Fatalf("identical pending requests must dedupe: %s vs %s (%s)", p1.ID, p2.ID, p1.Status)
	}
	if other := raiseFor(t, dir, "sess-other", "dev:python:exec"); other.ID == p1.ID {
		t.Fatal("a different session needs its own request")
	}
	list, _ := ListPendingApprovals(dir)
	if len(list) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(list))
	}

	// The human approves: the grant exists for the REQUESTING session and the agent can now use it.
	req, grant, err := DecidePendingApproval(dir, p1.ID, true)
	if err != nil || grant == nil || req.Status != "approved" || req.GrantID != grant.GrantID {
		t.Fatalf("approve failed: %v %+v", err, req)
	}
	if grant.SessionID != "sess-h" || len(grant.AllowedActions) != 1 || grant.AllowedActions[0] != "dev:python:exec" {
		t.Fatalf("grant must match the request: %+v", grant)
	}
	_, _, _, cErr := VerifyOrConsumeSessionZSPChecks(dir, "sess-h", "claude-code",
		[]ZSPActionCheck{{Action: "dev:python:exec", CanonicalResource: "workspace://current"}}, "python a.py", "", true, nil)
	if cErr != nil {
		t.Fatalf("approved grant must authorize the action, got %v", cErr)
	}
	// And only that session.
	_, _, _, oErr := VerifyOrConsumeSessionZSPChecks(dir, "sess-other", "claude-code",
		[]ZSPActionCheck{{Action: "dev:python:exec", CanonicalResource: "workspace://current"}}, "python a.py", "", true, nil)
	if oErr == nil {
		t.Fatal("approval must not leak to another session")
	}
}

func TestBAP936_DenyExpiryAndDoubleDecisionAreRefused(t *testing.T) {
	dir := t.TempDir()
	p := raiseFor(t, dir, "s1", "git:push:write")
	if _, _, err := DecidePendingApproval(dir, p.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecidePendingApproval(dir, p.ID, true); !errors.Is(err, ErrApprovalDecided) {
		t.Fatalf("a denied request cannot be approved later, got %v", err)
	}
	if _, _, err := DecidePendingApproval(dir, "req-nope", true); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	// Expiry.
	e := raiseFor(t, dir, "s2", "git:push:write")
	e.ExpiresAt = time.Now().Add(-time.Minute)
	if err := writeExpired(dir, e); err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecidePendingApproval(dir, e.ID, true); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("expired request must not be approvable, got %v", err)
	}
}

func TestBAP936_HardDenyIsNeverApprovableThroughARequest(t *testing.T) {
	dir := t.TempDir()
	p := raiseFor(t, dir, "s3", "aws:secretsmanager:read")
	if _, _, err := DecidePendingApproval(dir, p.ID, true); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("a credential request must stay un-grantable even when a human clicks approve, got %v", err)
	}
}
