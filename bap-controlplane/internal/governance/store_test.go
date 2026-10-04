package governance

import (
	"testing"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/policy"
	"bap-controlplane/pkg/types"
)

func setupTestStore() *Store {
	pStore := policy.NewStore("", "")
	aStore := audit.NewStore()
	return NewStore(pStore, aStore)
}

func TestImmutableProposalAndLineage(t *testing.T) {
	s := setupTestStore()

	// 1. Submit Proposal P1 (BAP-450)
	req := types.SubmitProposalRequest{
		AgentID:    "agent-claude-1",
		SessionID:  "sess-42",
		TaskID:     "task-100",
		HumanID:    "alice@company.com",
		Intent:     "BUG_FIX",
		Action:     "customer.address.update",
		Resource:   "customer/124",
		Parameters: map[string]any{"address": "123 Wrong St"},
	}

	p1, err := s.SubmitProposal(req)
	if err != nil {
		t.Fatalf("SubmitProposal failed: %v", err)
	}

	if p1.ProposalID == "" || p1.State != types.StateProposed {
		t.Fatalf("Invalid initial proposal state: %+v", p1)
	}

	// 2. Transition P1 to DENIED
	err = s.TransitionState(p1.ProposalID, types.StateDenied, "cedar-engine", "Resource customer/124 not found")
	if err != nil {
		t.Fatalf("TransitionState failed: %v", err)
	}

	// 3. Remediate P1 into P2 (BAP-451)
	remReq := types.RemediateProposalRequest{
		OperatorID: "operator-bob@company.com",
		Reason:     "Corrected customer ID from 124 to 123",
		Resource:   "customer/123",
		Parameters: map[string]any{"address": "123 Correct St"},
	}

	p2, err := s.RemediateProposal(p1.ProposalID, remReq)
	if err != nil {
		t.Fatalf("RemediateProposal failed: %v", err)
	}

	if p2.ParentProposalID != p1.ProposalID {
		t.Fatalf("Expected parent %s, got %s", p1.ProposalID, p2.ParentProposalID)
	}
	if p2.State != types.StateProposed {
		t.Fatalf("Remediated proposal must be PROPOSED, got %s", p2.State)
	}
	if p2.RemediatedBy != "operator-bob@company.com" {
		t.Fatalf("Expected RemediatedBy operator-bob, got %s", p2.RemediatedBy)
	}

	// Verify Parent P1 was NOT mutated (Rule R1)
	p1Reloaded, _ := s.GetProposal(p1.ProposalID)
	if p1Reloaded.Resource != "customer/124" || p1Reloaded.State != types.StateDenied {
		t.Fatalf("Parent proposal was mutated: %+v", p1Reloaded)
	}
}

func TestAntiSelfApprovalSeparationOfDuties(t *testing.T) {
	s := setupTestStore()

	req := types.SubmitProposalRequest{
		AgentID:  "agent-worker-1",
		HumanID:  "alice@company.com",
		Action:   "subscription.cancel",
		Resource: "subscription/789",
	}
	p, err := s.SubmitProposal(req)
	if err != nil {
		t.Fatalf("SubmitProposal failed: %v", err)
	}

	// Submit proposal transition to evaluating
	_ = s.TransitionState(p.ProposalID, types.StateEvaluating, "bap-core", "Evaluating")

	// Alice tries to approve her own proposal -> MUST FAIL (BAP-453)
	err = s.ApproveProposal(p.ProposalID, types.ApproveProposalRequest{
		ApproverID: "alice@company.com",
		Reason:     "Self-approval attempt",
	})
	if err == nil {
		t.Fatalf("Expected anti-self-approval rejection, but approval succeeded!")
	}

	// Remediator tries to approve proposal they remediated -> MUST FAIL
	remReq := types.RemediateProposalRequest{
		OperatorID: "operator-bob@company.com",
		Reason:     "Updated parameters",
	}
	child, _ := s.RemediateProposal(p.ProposalID, remReq)
	_ = s.TransitionState(child.ProposalID, types.StateEvaluating, "bap-core", "Evaluating")

	err = s.ApproveProposal(child.ProposalID, types.ApproveProposalRequest{
		ApproverID: "operator-bob@company.com",
		Reason:     "Operator self-approval attempt",
	})
	if err == nil {
		t.Fatalf("Expected operator anti-self-approval rejection, but approval succeeded!")
	}

	// Independent manager approves -> SUCCEEDS
	err = s.ApproveProposal(child.ProposalID, types.ApproveProposalRequest{
		ApproverID: "manager-charlie@company.com",
		Reason:     "Authorized by tier-2 manager",
	})
	if err != nil {
		t.Fatalf("Independent approval failed: %v", err)
	}

	reloaded, _ := s.GetProposal(child.ProposalID)
	if reloaded.State != types.StateAuthorized || reloaded.ApproverID != "manager-charlie@company.com" {
		t.Fatalf("Unexpected state after valid approval: %+v", reloaded)
	}
}

func TestLifecycleStateTransitions(t *testing.T) {
	s := setupTestStore()

	p, _ := s.SubmitProposal(types.SubmitProposalRequest{
		AgentID:  "agent-1",
		Action:   "order.create",
		Resource: "orders/1",
	})

	// Illegal jump directly from PROPOSED to COMMITTED must be rejected (BAP-455)
	err := s.TransitionState(p.ProposalID, types.StateCommitted, "attacker", "Bypassing PEP")
	if err == nil {
		t.Fatalf("Illegal state jump should have been rejected!")
	}

	// Valid sequence: PROPOSED -> EVALUATING -> AUTHORIZED -> GRANTED -> PRESENTED -> PEP_ALLOWED -> EXECUTING -> COMMITTED -> COMPLETED
	steps := []types.ActionLifecycleState{
		types.StateEvaluating,
		types.StateAuthorized,
		types.StateGranted,
		types.StatePresented,
		types.StatePEPAllowed,
		types.StateExecuting,
		types.StateCommitted,
		types.StateCompleted,
	}

	for _, step := range steps {
		if err := s.TransitionState(p.ProposalID, step, "system", "Standard progression"); err != nil {
			t.Fatalf("Valid transition to %s failed: %v", step, err)
		}
	}

	reloaded, _ := s.GetProposal(p.ProposalID)
	if reloaded.State != types.StateCompleted {
		t.Fatalf("Expected final state COMPLETED, got %s", reloaded.State)
	}
	if len(reloaded.StateHistory) != 9 { // 1 initial + 8 transitions
		t.Fatalf("Expected 9 history transitions, got %d", len(reloaded.StateHistory))
	}
}

func TestReconciliationAndOrphanDetection(t *testing.T) {
	s := setupTestStore()

	// 1. Create a proposal stuck in GRANTED
	p1, _ := s.SubmitProposal(types.SubmitProposalRequest{AgentID: "a1", Action: "act1", Resource: "res1"})
	_ = s.TransitionState(p1.ProposalID, types.StateEvaluating, "sys", "")
	_ = s.TransitionState(p1.ProposalID, types.StateAuthorized, "sys", "")
	_ = s.TransitionState(p1.ProposalID, types.StateGranted, "sys", "")

	// 2. Create a proposal stuck in PEP_ALLOWED (downstream execution never confirmed)
	p2, _ := s.SubmitProposal(types.SubmitProposalRequest{AgentID: "a2", Action: "act2", Resource: "res2"})
	_ = s.TransitionState(p2.ProposalID, types.StateEvaluating, "sys", "")
	_ = s.TransitionState(p2.ProposalID, types.StateAuthorized, "sys", "")
	_ = s.TransitionState(p2.ProposalID, types.StateGranted, "sys", "")
	_ = s.TransitionState(p2.ProposalID, types.StatePresented, "sys", "")
	_ = s.TransitionState(p2.ProposalID, types.StatePEPAllowed, "sys", "")

	// Artificially age the proposals
	s.mu.Lock()
	s.proposals[p1.ProposalID].UpdatedAt = time.Now().UTC().Add(-10 * time.Minute)
	s.proposals[p2.ProposalID].UpdatedAt = time.Now().UTC().Add(-10 * time.Minute)
	s.mu.Unlock()

	// Run reconciliation (BAP-456)
	report := s.ReconcileOrphans(5 * time.Minute)
	if report.ReconciledCount != 2 {
		t.Fatalf("Expected 2 reconciled proposals, got %d", report.ReconciledCount)
	}

	rel1, _ := s.GetProposal(p1.ProposalID)
	if rel1.State != types.StateExpired {
		t.Fatalf("Unpresented grant must become EXPIRED, got %s", rel1.State)
	}

	rel2, _ := s.GetProposal(p2.ProposalID)
	if rel2.State != types.StateUnknown {
		t.Fatalf("Unconfirmed execution must become UNKNOWN, got %s", rel2.State)
	}
}

func TestInvestigationTimelineReconstruction(t *testing.T) {
	s := setupTestStore()

	// Create root proposal and child remediation
	p1, _ := s.SubmitProposal(types.SubmitProposalRequest{
		AgentID:  "agent-1",
		TaskID:   "task-fix-database",
		Action:   "db.drop",
		Resource: "production/db",
	})
	_ = s.TransitionState(p1.ProposalID, types.StateDenied, "cedar", "Forbid drop")

	p2, _ := s.RemediateProposal(p1.ProposalID, types.RemediateProposalRequest{
		OperatorID: "operator-dave",
		Reason:     "Changed to read-only backup",
		Action:     "db.backup",
		Resource:   "production/db",
	})
	_ = s.TransitionState(p2.ProposalID, types.StateEvaluating, "sys", "")
	_ = s.TransitionState(p2.ProposalID, types.StateAuthorized, "sys", "")

	// Reconstruct timeline (BAP-458, BAP-459)
	timeline, err := s.GetTimeline(p2.ProposalID)
	if err != nil {
		t.Fatalf("GetTimeline failed: %v", err)
	}

	if timeline.RootProposal != p1.ProposalID {
		t.Fatalf("Expected root proposal %s, got %s", p1.ProposalID, timeline.RootProposal)
	}
	if len(timeline.Lineage) != 2 {
		t.Fatalf("Expected lineage length 2, got %d", len(timeline.Lineage))
	}
	if len(timeline.Nodes) < 3 {
		t.Fatalf("Expected at least 3 evidence nodes, got %d", len(timeline.Nodes))
	}
}
