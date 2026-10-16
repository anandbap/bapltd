package hitl

import (
	"strings"
	"testing"
	"time"
)

func TestEscalationManager_ContextualEscalationAndApproval(t *testing.T) {
	em := NewEscalationManager("test-hitl-secret-key", 2*time.Second, 3)

	// 1. Submit an escalation request for out-of-scope S3 upload
	req, err := em.RequestEscalation(
		"task-migrate-001",
		"sess-worker-77",
		"agent-cloud-migrator",
		"s3://external-team-audit-logs/backup.tar.gz",
		"s3:PutObject",
		"Need to archive pre-migration logs to central audit bucket",
	)
	if err != nil {
		t.Fatalf("expected successful escalation request, got err: %v", err)
	}

	if req.Status != StatusPending {
		t.Errorf("expected StatusPending, got %s", req.Status)
	}
	if req.RiskRating != RiskHigh {
		t.Errorf("expected RiskHigh for S3 write, got %s", req.RiskRating)
	}

	// 2. Human reviewer approves escalation
	res, err := em.ResolveEscalation(req.EscalationID, "approve", "lead-reviewer@company.internal", 5*time.Minute)
	if err != nil {
		t.Fatalf("expected successful resolution, got err: %v", err)
	}

	if res.Status != StatusApproved {
		t.Errorf("expected StatusApproved, got %s", res.Status)
	}
	if !strings.HasPrefix(res.EphemeralGrant, "task-grant-task-migrate-001-s3:PutObject-") {
		t.Errorf("expected task-scoped ephemeral grant, got %s", res.EphemeralGrant)
	}
	if res.ExpiresAt == nil || res.ExpiresAt.Before(time.Now()) {
		t.Error("expected valid future expiration for task grant")
	}

	// 3. Resolving again must fail
	_, errDouble := em.ResolveEscalation(req.EscalationID, "deny", "another@company.internal", 0)
	if errDouble == nil {
		t.Fatal("expected error on already resolved escalation")
	}
}

func TestEscalationManager_ApprovalFatigueThrottling(t *testing.T) {
	em := NewEscalationManager("test-hitl-secret-key", 2*time.Second, 5)

	// 1. First request succeeds
	_, err1 := em.RequestEscalation(
		"task-deploy-42",
		"sess-1",
		"agent-1",
		"production-db",
		"drop_database",
		"Cleaning up old tables",
	)
	if err1 != nil {
		t.Fatalf("expected first request to succeed, got err: %v", err1)
	}

	// 2. Immediate duplicate request MUST be throttled (Approval Fatigue Prevention)
	_, errDuplicate := em.RequestEscalation(
		"task-deploy-42",
		"sess-1",
		"agent-1",
		"production-db",
		"drop_database",
		"Cleaning up old tables",
	)
	if errDuplicate == nil {
		t.Fatal("expected duplicate escalation request to be throttled")
	}
	if !strings.Contains(errDuplicate.Error(), "ApprovalFatigueThrottled") {
		t.Errorf("expected ApprovalFatigueThrottled error, got %v", errDuplicate)
	}

	// 3. Requesting a DIFFERENT action or resource on the same task succeeds
	reqDifferent, errDiff := em.RequestEscalation(
		"task-deploy-42",
		"sess-1",
		"agent-1",
		"staging-db",
		"read_schema",
		"Inspecting staging schema",
	)
	if errDiff != nil {
		t.Fatalf("expected different action to pass without throttling, got %v", errDiff)
	}
	if reqDifferent.RiskRating != RiskLow {
		t.Errorf("expected RiskLow, got %s", reqDifferent.RiskRating)
	}

	// 4. Wait out cooldown duration -> duplicate now succeeds
	time.Sleep(2100 * time.Millisecond)
	_, errAfterCooldown := em.RequestEscalation(
		"task-deploy-42",
		"sess-1",
		"agent-1",
		"production-db",
		"drop_database",
		"Retrying request after cooldown",
	)
	if errAfterCooldown != nil {
		t.Fatalf("expected request after cooldown to succeed, got %v", errAfterCooldown)
	}
}

func TestEscalationManager_MaxAttemptsExceeded(t *testing.T) {
	// Set max attempts = 2, cooldown = 1ms
	em := NewEscalationManager("test-hitl-secret-key", 1*time.Millisecond, 2)

	_, err1 := em.RequestEscalation("task-limited-1", "sess-1", "agent-1", "res-1", "action-1", "reason 1")
	if err1 != nil {
		t.Fatal(err1)
	}
	time.Sleep(2 * time.Millisecond)

	_, err2 := em.RequestEscalation("task-limited-1", "sess-1", "agent-1", "res-2", "action-2", "reason 2")
	if err2 != nil {
		t.Fatal(err2)
	}
	time.Sleep(2 * time.Millisecond)

	// 3rd attempt exceeds max attempts (2)
	_, err3 := em.RequestEscalation("task-limited-1", "sess-1", "agent-1", "res-3", "action-3", "reason 3")
	if err3 == nil {
		t.Fatal("expected 3rd attempt to fail with MaxEscalationAttemptsExceeded")
	}
	if !strings.Contains(err3.Error(), "MaxEscalationAttemptsExceeded") {
		t.Errorf("expected MaxEscalationAttemptsExceeded, got %v", err3)
	}
}
