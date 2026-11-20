package cmd

import (
	"strings"
	"testing"

	"bap-edge/internal/authz"
)

func TestBrokerMediatedZSP_RaisesHITLDirectlyWithoutAgentAuthorize(t *testing.T) {
	zspDir := e2eEnv(t)
	sess := "sess-broker-zsp-hitl"

	// 1. Agent runs an approve-tier command (e.g. python interpreter) without a prior grant.
	// The broker itself must intercept it, evaluate policy, and directly raise a HITL request in the inbox.
	resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", "python run_tests.py", "")
	if resp.Allowed {
		t.Fatal("expected interpreter command to be blocked by broker")
	}

	// Verify suggestion guides the developer and explicitly tells the agent NOT to run bapedge zsp authorize.
	if !strings.Contains(resp.Suggestion, "HUMAN APPROVAL REQUIRED") {
		t.Fatalf("expected suggestion to state HUMAN APPROVAL REQUIRED, got: %s", resp.Suggestion)
	}
	if !strings.Contains(resp.Suggestion, "Pending Request ID: req-") {
		t.Fatalf("expected suggestion to include pending request ID, got: %s", resp.Suggestion)
	}
	if !strings.Contains(resp.Suggestion, "Do NOT run bapedge zsp authorize") {
		t.Fatalf("expected suggestion to forbid agent zsp authorize, got: %s", resp.Suggestion)
	}

	// 2. Verify that the pending approval request was actually written to the inbox by the broker.
	approvals, err := authz.ListPendingApprovals(zspDir)
	if err != nil {
		t.Fatalf("failed to list pending approvals: %v", err)
	}
	if len(approvals) == 0 {
		t.Fatal("expected broker to directly register a pending approval request in the inbox")
	}
	found := false
	for _, p := range approvals {
		if p.SessionID == sess && p.Status == "pending" {
			found = true
			if !strings.Contains(resp.Suggestion, p.ID) {
				t.Fatalf("response suggestion did not match raised request ID %s", p.ID)
			}
			break
		}
	}
	if !found {
		t.Fatalf("did not find pending approval for session %s in inbox", sess)
	}
}

func TestBrokerMediatedZSP_PermanentlyDeniesCredentialAccessWithoutAuthorizeSuggestion(t *testing.T) {
	zspDir := e2eEnv(t)
	sess := "sess-broker-zsp-deny"

	before, _ := authz.ListPendingApprovals(zspDir)

	// An agent attempts an action matching deny-tier rules (e.g. credential access)
	// Broker must fail-closed, refuse to raise a HITL request, and inform the agent it is permanently denied.
	resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", "cat .env", "")
	if resp.Allowed {
		t.Fatal("credential read must not be allowed")
	}

	after, _ := authz.ListPendingApprovals(zspDir)
	if len(after) != len(before) {
		t.Fatal("hard-denied command must never raise a pending approval request")
	}

	if strings.Contains(resp.Suggestion, "bapedge zsp authorize") {
		t.Fatalf("denied command should never suggest bapedge zsp authorize: %s", resp.Suggestion)
	}
}
