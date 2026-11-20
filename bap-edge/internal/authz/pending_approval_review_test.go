package authz

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestReviewedApprovalRejectsChangedRequestBeforeMinting(t *testing.T) {
	for _, change := range []string{"actions", "resources", "session", "linked-session", "goal", "uses", "ttl", "expiry"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			p, err := RaisePendingApproval(dir, PendingApproval{SessionID: "fixture-session", ClientType: "codex", Actions: []string{"fs:file:write"}, Resources: []string{"workspace://current"}, MaxUses: 1})
			if err != nil {
				t.Fatal(err)
			}
			reviewed, _ := GetPendingApproval(dir, p.ID)
			switch change {
			case "actions":
				p.Actions = []string{"git:push:write"}
			case "resources":
				p.Resources = []string{"system://local"}
			case "session":
				p.SessionID = "other-session"
			case "linked-session":
				p.RequestingSessionID = "another-agent"
			case "goal":
				p.Goal = "changed intent"
			case "uses":
				p.MaxUses = 100
			case "ttl":
				p.TTLSeconds = 10000
			case "expiry":
				p.ExpiresAt = p.ExpiresAt.Add(1)
			}
			raw, _ := json.Marshal(p)
			if err := writeFileAtomic(approvalPath(dir, p.ID), raw, 0600); err != nil {
				t.Fatal(err)
			}
			_, grant, err := DecidePendingApprovalReviewed(dir, p.ID, true, *reviewed)
			if !errors.Is(err, ErrApprovalChanged) || grant != nil {
				t.Fatalf("changed request minted: %+v %v", grant, err)
			}
			still, _ := GetPendingApproval(dir, p.ID)
			if still.Status != "pending" || still.GrantID != "" {
				t.Fatal("refusal changed authority", still)
			}
		})
	}
}

func TestReviewedApprovalMintsOnlyOnceForUnchangedFixture(t *testing.T) {
	dir, _ := batchFixture(t)
	p := raiseFor(t, dir, "reviewed-fixture", "dev:python:exec")
	reviewed, err := GetPendingApproval(dir, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	decided, grant, err := DecidePendingApprovalReviewed(dir, p.ID, true, *reviewed)
	if err != nil || grant == nil || decided.Status != "approved" || grant.SessionID != reviewed.SessionID {
		t.Fatalf("unchanged fixture refused: %+v %v", decided, err)
	}
	if _, second, err := DecidePendingApprovalReviewed(dir, p.ID, true, *reviewed); !errors.Is(err, ErrApprovalDecided) || second != nil {
		t.Fatalf("review replay minted another grant: %+v %v", second, err)
	}
}
