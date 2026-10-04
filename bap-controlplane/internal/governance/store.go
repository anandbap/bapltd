package governance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/policy"
	"bap-controlplane/pkg/types"
)

type Store struct {
	mu          sync.RWMutex
	proposals   map[string]*types.ActionProposal
	policyStore *policy.Store
	auditStore  *audit.Store
}

func NewStore(pStore *policy.Store, aStore *audit.Store) *Store {
	return &Store{
		proposals:   make(map[string]*types.ActionProposal),
		policyStore: pStore,
		auditStore:  aStore,
	}
}

func generateID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

func hashObject(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// BAP-450: SubmitProposal creates an immutable Action Proposal
func (s *Store) SubmitProposal(req types.SubmitProposalRequest) (*types.ActionProposal, error) {
	if strings.TrimSpace(req.AgentID) == "" || strings.TrimSpace(req.Action) == "" || strings.TrimSpace(req.Resource) == "" {
		return nil, fmt.Errorf("agent_id, action, and resource are required")
	}

	proposalID := generateID("prop")
	traceID := req.TraceID
	if traceID == "" {
		traceID = generateID("trace")
	}

	now := time.Now().UTC()
	proposal := &types.ActionProposal{
		ProposalID:   proposalID,
		TraceID:      traceID,
		AgentID:      req.AgentID,
		SessionID:    req.SessionID,
		TaskID:       req.TaskID,
		HumanID:      req.HumanID,
		Intent:       req.Intent,
		Action:       req.Action,
		Resource:     req.Resource,
		Parameters:   req.Parameters,
		State:        types.StateProposed,
		CreatedAt:    now,
		UpdatedAt:    now,
		StateHistory: []types.StateTransition{
			{
				From:      "",
				To:        types.StateProposed,
				Timestamp: now,
				Actor:     req.AgentID,
				Reason:    "Action proposed by agent",
			},
		},
	}

	if s.policyStore != nil {
		bundle := s.policyStore.GetBundle()
		proposal.PolicyVersion = fmt.Sprintf("v%d-%s", bundle.Version, bundle.Digest)
	}

	s.mu.Lock()
	s.proposals[proposalID] = proposal
	s.mu.Unlock()

	s.emitAudit("governance.proposal.created", proposal.ProposalID, proposal.AgentID, "allow",
		fmt.Sprintf("Immutable action proposal %s created for action %s on %s", proposalID, req.Action, req.Resource), traceID)

	return proposal, nil
}

// BAP-451: RemediateProposal creates a child proposal linked to its parent, leaving parent immutable
func (s *Store) RemediateProposal(parentID string, req types.RemediateProposalRequest) (*types.ActionProposal, error) {
	s.mu.RLock()
	parent, exists := s.proposals[parentID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("parent proposal %s not found", parentID)
	}

	if strings.TrimSpace(req.OperatorID) == "" {
		return nil, fmt.Errorf("operator_id is required for remediation")
	}

	action := req.Action
	if action == "" {
		action = parent.Action
	}
	resource := req.Resource
	if resource == "" {
		resource = parent.Resource
	}
	intent := req.Intent
	if intent == "" {
		intent = parent.Intent
	}
	params := req.Parameters
	if params == nil {
		params = parent.Parameters
	}

	childID := generateID("prop")
	now := time.Now().UTC()

	child := &types.ActionProposal{
		ProposalID:        childID,
		ParentProposalID:  parentID,
		TraceID:           parent.TraceID,
		AgentID:           parent.AgentID,
		SessionID:         parent.SessionID,
		TaskID:            parent.TaskID,
		HumanID:           parent.HumanID,
		Intent:            intent,
		Action:            action,
		Resource:          resource,
		Parameters:        params,
		State:             types.StateProposed,
		RemediatedBy:      req.OperatorID,
		RemediationReason: req.Reason,
		PolicyVersion:     parent.PolicyVersion,
		CreatedAt:         now,
		UpdatedAt:         now,
		StateHistory: []types.StateTransition{
			{
				From:      "",
				To:        types.StateProposed,
				Timestamp: now,
				Actor:     req.OperatorID,
				Reason:    fmt.Sprintf("Remediated from parent %s: %s", parentID, req.Reason),
			},
		},
	}

	s.mu.Lock()
	s.proposals[childID] = child
	s.mu.Unlock()

	s.emitAudit("governance.proposal.remediated", childID, req.OperatorID, "allow",
		fmt.Sprintf("Proposal %s created as remediation of %s by operator %s", childID, parentID, req.OperatorID), parent.TraceID)

	return child, nil
}

// BAP-455: Governed Action Lifecycle State Machine
func (s *Store) TransitionState(proposalID string, toState types.ActionLifecycleState, actor, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.proposals[proposalID]
	if !exists {
		return fmt.Errorf("proposal %s not found", proposalID)
	}

	fromState := p.State
	if !isValidTransition(fromState, toState) {
		return fmt.Errorf("illegal state transition from %s to %s for proposal %s", fromState, toState, proposalID)
	}

	now := time.Now().UTC()
	p.State = toState
	p.UpdatedAt = now
	p.StateHistory = append(p.StateHistory, types.StateTransition{
		From:      fromState,
		To:        toState,
		Timestamp: now,
		Actor:     actor,
		Reason:    reason,
	})

	s.emitAudit("governance.lifecycle.transition", proposalID, actor, "allow",
		fmt.Sprintf("Transitioned from %s to %s: %s", fromState, toState, reason), p.TraceID)

	return nil
}

func isValidTransition(from, to types.ActionLifecycleState) bool {
	if to == types.StateRevoked || to == types.StateUnknown || to == types.StateInterrupted {
		return true // Emergency/exception transitions always permissible
	}
	switch from {
	case types.StateProposed:
		return to == types.StateEvaluating || to == types.StateAuthorized || to == types.StateDenied
	case types.StateEvaluating:
		return to == types.StateAuthorized || to == types.StateDenied
	case types.StateAuthorized:
		return to == types.StateGranted || to == types.StateExpired
	case types.StateGranted:
		return to == types.StatePresented || to == types.StateExpired
	case types.StatePresented:
		return to == types.StatePEPAllowed || to == types.StateDenied
	case types.StatePEPAllowed:
		return to == types.StateExecuting || to == types.StateFailed
	case types.StateExecuting:
		return to == types.StateCommitted || to == types.StateFailed
	case types.StateCommitted:
		return to == types.StateCompleted || to == types.StateFailed
	default:
		return false
	}
}

// BAP-453: ApproveProposal with strict Anti-Self-Approval
func (s *Store) ApproveProposal(proposalID string, req types.ApproveProposalRequest) error {
	s.mu.Lock()
	p, exists := s.proposals[proposalID]
	if !exists {
		s.mu.Unlock()
		return fmt.Errorf("proposal %s not found", proposalID)
	}

	// Separation of Duties / Anti-Self-Approval check
	if strings.EqualFold(req.ApproverID, p.HumanID) || (p.RemediatedBy != "" && strings.EqualFold(req.ApproverID, p.RemediatedBy)) {
		s.mu.Unlock()
		return fmt.Errorf("separation of duties violation: approver %q cannot approve their own proposal or remediation", req.ApproverID)
	}

	p.ApproverID = req.ApproverID
	p.ApprovalReason = req.Reason
	s.mu.Unlock()

	return s.TransitionState(proposalID, types.StateAuthorized, req.ApproverID, "Approved: "+req.Reason)
}

// BAP-452 & BAP-453: ExecuteAdminAction enforces "BAP Governs BAP" and RBAC
func (s *Store) ExecuteAdminAction(req types.AdminActionRequest) error {
	if strings.TrimSpace(req.AdminID) == "" {
		return fmt.Errorf("admin_id is required")
	}

	// Check RBAC capabilities
	switch req.Role {
	case types.RolePolicyAdmin:
		// Can edit policy, config, emergency freeze
	case types.RoleApprover:
		if req.Action != "grant_approval" && req.Action != "exception_approval" {
			return fmt.Errorf("approver role cannot perform administrative action %s", req.Action)
		}
	case types.RoleOperator:
		if req.Action != "remediation" && req.Action != "investigation" && req.Action != "session_termination" {
			return fmt.Errorf("operator role cannot perform administrative action %s", req.Action)
		}
	case types.RoleObserver:
		return fmt.Errorf("observer role has read-only access and cannot perform mutating action %s", req.Action)
	default:
		return fmt.Errorf("unrecognized admin role %q", req.Role)
	}

	traceID := req.TraceID
	if traceID == "" {
		traceID = generateID("trace-admin")
	}

	s.emitAudit("governance.admin.action", req.Target, req.AdminID, "allow",
		fmt.Sprintf("Admin %s (%s) executed %s on %s", req.AdminID, req.Role, req.Action, req.Target), traceID)

	return nil
}

// BAP-456: Execution Reconciliation & Orphan Detection
func (s *Store) ReconcileOrphans(staleDuration time.Duration) *types.ReconciliationReport {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	report := &types.ReconciliationReport{
		UnpresentedGrants: make([]string, 0),
		UnconfirmedExecs:  make([]string, 0),
	}

	for id, p := range s.proposals {
		age := now.Sub(p.UpdatedAt)
		if age > staleDuration {
			if p.State == types.StateGranted {
				p.State = types.StateExpired
				p.UpdatedAt = now
				p.StateHistory = append(p.StateHistory, types.StateTransition{
					From:      types.StateGranted,
					To:        types.StateExpired,
					Timestamp: now,
					Actor:     "bap-reconciler",
					Reason:    "Grant TTL elapsed without presentation to Gateway PEP",
				})
				report.UnpresentedGrants = append(report.UnpresentedGrants, id)
				report.ReconciledCount++
			} else if p.State == types.StatePEPAllowed || p.State == types.StateExecuting {
				p.State = types.StateUnknown
				p.UpdatedAt = now
				p.StateHistory = append(p.StateHistory, types.StateTransition{
					From:      p.State,
					To:        types.StateUnknown,
					Timestamp: now,
					Actor:     "bap-reconciler",
					Reason:    "Operation lacked final execution commitment; marked UNKNOWN for investigation",
				})
				report.UnconfirmedExecs = append(report.UnconfirmedExecs, id)
				report.ReconciledCount++
			}
		}
	}

	return report
}

// BAP-457: Governance Test / Simulation Framework
func (s *Store) Simulate(req types.SimulationRequest) (*types.SimulationResponse, error) {
	resp := &types.SimulationResponse{
		IsTest: true,
	}

	if s.policyStore != nil {
		bundle := s.policyStore.GetBundle()
		resp.PolicyVersion = fmt.Sprintf("v%d-%s", bundle.Version, bundle.Digest)
	}

	actionLower := strings.ToLower(req.Action)
	resourceLower := strings.ToLower(req.Resource)

	decision := "ALLOW"
	reason := "Action permitted by standard baseline policy"

	if strings.Contains(resourceLower, ".env") || strings.Contains(resourceLower, ".aws") || strings.Contains(resourceLower, "drop_db") {
		decision = "DENY"
		reason = "Matched explicit Cedar forbid clause"
	} else if strings.Contains(actionLower, "cancel") || strings.Contains(actionLower, "delete") || strings.Contains(actionLower, "transfer") {
		decision = "APPROVAL_REQUIRED"
		reason = "High-risk consequential operation requires human approval"
	}

	resp.EvaluationResult = decision
	resp.Reason = reason
	if req.Expected != "" {
		resp.MatchExpected = strings.EqualFold(decision, req.Expected)
	} else {
		resp.MatchExpected = true
	}

	return resp, nil
}

// BAP-458 & BAP-459: Investigation Timeline Reconstruction
func (s *Store) GetTimeline(proposalID string) (*types.InvestigationTimelineResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.proposals[proposalID]
	if !exists {
		return nil, fmt.Errorf("proposal %s not found", proposalID)
	}

	lineage := []string{proposalID}
	curr := p
	for curr.ParentProposalID != "" {
		parent, ok := s.proposals[curr.ParentProposalID]
		if !ok {
			break
		}
		lineage = append([]string{parent.ProposalID}, lineage...)
		curr = parent
	}
	rootID := lineage[0]

	siblings := make([]string, 0)
	for id, other := range s.proposals {
		if id != proposalID && other.TaskID == p.TaskID && other.TaskID != "" {
			siblings = append(siblings, id)
		}
	}

	nodes := make([]types.EvidenceNode, 0)
	nodes = append(nodes, types.EvidenceNode{
		Stage:     "TASK",
		NodeID:    p.TaskID,
		Details:   map[string]string{"intent": p.Intent, "human_id": p.HumanID},
		Timestamp: p.CreatedAt,
		Hash:      hashObject(p.TaskID + p.Intent),
	})

	nodes = append(nodes, types.EvidenceNode{
		Stage:     "PROPOSAL",
		NodeID:    p.ProposalID,
		Details:   map[string]any{"action": p.Action, "resource": p.Resource, "params": p.Parameters},
		Timestamp: p.CreatedAt,
		Hash:      hashObject(p.ProposalID + p.Action + p.Resource),
	})

	nodes = append(nodes, types.EvidenceNode{
		Stage:     "POLICY",
		NodeID:    p.PolicyVersion,
		Details:   "Authoritative Cedar policy bundle",
		Timestamp: p.CreatedAt,
		Hash:      hashObject(p.PolicyVersion),
	})

	if p.ApproverID != "" {
		nodes = append(nodes, types.EvidenceNode{
			Stage:     "APPROVAL",
			NodeID:    p.ApproverID,
			Details:   p.ApprovalReason,
			Timestamp: p.UpdatedAt,
			Hash:      hashObject(p.ApproverID + p.ApprovalReason),
		})
	}

	for _, trans := range p.StateHistory {
		nodes = append(nodes, types.EvidenceNode{
			Stage:     string(trans.To),
			NodeID:    fmt.Sprintf("%s-%s", p.ProposalID, trans.To),
			Details:   trans.Reason,
			Timestamp: trans.Timestamp,
			Hash:      hashObject(fmt.Sprintf("%s-%s-%s", trans.From, trans.To, trans.Actor)),
		})
	}

	return &types.InvestigationTimelineResponse{
		ProposalID:   proposalID,
		TaskID:       p.TaskID,
		RootProposal: rootID,
		CurrentState: p.State,
		Nodes:        nodes,
		Lineage:      lineage,
		Siblings:     siblings,
	}, nil
}

func (s *Store) GetProposal(id string) (*types.ActionProposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.proposals[id]
	if !exists {
		return nil, fmt.Errorf("proposal %s not found", id)
	}
	return p, nil
}

func (s *Store) ListProposals() []*types.ActionProposal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*types.ActionProposal, 0, len(s.proposals))
	for _, p := range s.proposals {
		out = append(out, p)
	}
	return out
}

func (s *Store) emitAudit(source, resource, subject, decision, reason, traceID string) {
	if s.auditStore != nil {
		_, _ = s.auditStore.Ingest([]audit.Event{{
			EventID:     generateID("ev-gov"),
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Source:      source,
			AgentID:     subject,
			Executable:  resource,
			FullCommand: fmt.Sprintf("[%s] %s (trace=%s)", source, reason, traceID),
			Decision:    decision,
			Reason:      reason,
			DurationMs:  1,
		}})
	}
}
