package authz

import (
	"errors"
	"testing"
)

// BAP-1104: step-up auto-approve is a convenience for build/test style approve-tier requests. It must
// never mint a grant for publishing, destructive, administrative or network-egress effects.
func TestAutoApproveNeverCoversPublishDeleteAdminOrEgress(t *testing.T) {
	prev := AutoApproveActive
	t.Cleanup(func() { AutoApproveActive = prev })
	AutoApproveActive = func() bool { return true }

	zspDir := t.TempDir()
	ask := func(sess, resource string, actions ...string) error {
		_, _, err := SubmitTaskEnvelopeWithDelegation(zspDir, sess, "claude-code", "TASK_EXECUTION", "work", "work",
			actions, []string{resource}, "", DelegationAutoApprove, 1, 0)
		return err
	}

	for _, act := range []string{"git:push", "git:push:write", "fs:file:delete", "db:table:drop", "svc:admin"} {
		if err := ask("sess-never-"+act, "workspace://current", act); !errors.Is(err, ErrHighRiskApprovalRequired) {
			t.Errorf("auto-approve must not cover %s, got %v", act, err)
		}
	}
	if err := ask("sess-never-egress", "https://example.test/x", "http:get"); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Errorf("auto-approve must not cover network egress, got %v", err)
	}

	// A mixed ask is refused as a whole: an auto-approvable action cannot smuggle a push along.
	if err := ask("sess-never-mixed", "workspace://current", "dev:go:-C", "git:push:write"); !errors.Is(err, ErrHighRiskApprovalRequired) {
		t.Errorf("a mixed ask containing a push must be refused, got %v", err)
	}

	// Ordinary approve-tier work is still covered.
	if err := ask("sess-ok", "workspace://current", "dev:go:-C"); err != nil {
		t.Errorf("auto-approve should still cover an ordinary approve-tier build/test request: %v", err)
	}
}

func TestNoAutoApproveFlagComesFromPolicyData(t *testing.T) {
	p := defaultPolicyForTest(t)
	if d := p.decide("git:push:write", "workspace://current"); d.Tier != TierApprove || !d.NoAutoApprove {
		t.Fatalf("git push must be approve-tier and no_auto_approve, got %+v", d)
	}
	if d := p.decide("dev:go:-C", "workspace://current"); d.Tier != TierApprove || d.NoAutoApprove {
		t.Fatalf("an ordinary build must stay auto-approvable, got %+v", d)
	}
}
