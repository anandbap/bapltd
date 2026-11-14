package authz

import (
	"testing"
	"time"
)

func TestFindLiveApprovedGrantReusesOnlyHumanApprovedCoveredGrant(t *testing.T) {
	dir := t.TempDir()
	actions := []string{"dev:python:exec"}
	resources := []string{escalationWorkspace}
	now := time.Now()

	// A pending (undecided) request never yields a grant.
	p := raiseFor(t, dir, "sess-r", "dev:python:exec")
	if g, _ := FindLiveApprovedGrant(dir, "sess-r", "claude-code", actions, resources, now); g != nil {
		t.Fatal("a pending request must not produce a reusable grant")
	}

	_, grant, err := DecidePendingApproval(dir, p.ID, true)
	if err != nil || grant == nil {
		t.Fatalf("approve failed: %v", err)
	}

	g, a := FindLiveApprovedGrant(dir, "sess-r", "claude-code", actions, resources, now)
	if g == nil || a == nil || g.GrantID != grant.GrantID || a.ID != p.ID {
		t.Fatalf("expected the approved grant to be reused, got %+v %+v", g, a)
	}

	// Another session never inherits it.
	if g, _ := FindLiveApprovedGrant(dir, "sess-other", "claude-code", actions, resources, now); g != nil {
		t.Fatal("approval must not leak to another session")
	}
	// A broader ask is not covered, so it must raise its own request.
	if g, _ := FindLiveApprovedGrant(dir, "sess-r", "claude-code", []string{"dev:python:exec", "git:push:write"}, resources, now); g != nil {
		t.Fatal("a broader ask must not reuse a narrower grant")
	}
	if g, _ := FindLiveApprovedGrant(dir, "sess-r", "claude-code", actions, []string{"workspace://elsewhere"}, now); g != nil {
		t.Fatal("a different resource must not reuse the grant")
	}
	// Once expired it is gone.
	if g, _ := FindLiveApprovedGrant(dir, "sess-r", "claude-code", actions, resources, grant.ExpiresAt.Add(time.Second)); g != nil {
		t.Fatal("an expired grant must not be reused")
	}
}

func TestFindLiveApprovedGrantIgnoresDeniedRequests(t *testing.T) {
	dir := t.TempDir()
	p := raiseFor(t, dir, "sess-d", "git:push:write")
	if _, _, err := DecidePendingApproval(dir, p.ID, false); err != nil {
		t.Fatal(err)
	}
	if g, _ := FindLiveApprovedGrant(dir, "sess-d", "claude-code", []string{"git:push:write"}, []string{escalationWorkspace}, time.Now()); g != nil {
		t.Fatal("a denied request must never yield a grant")
	}
}
