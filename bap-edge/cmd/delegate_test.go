package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/audit"
)

func TestVerifyLocalAttenuation(t *testing.T) {
	// 1. Valid subset
	parentScopes := []string{"fs:read", "fs:write", "net:egress"}
	childScopesValid := []string{"fs:read"}
	if err := VerifyLocalAttenuation(parentScopes, childScopesValid, "/workspace/*", "/workspace/src/*", "exec", "exec"); err != nil {
		t.Fatalf("expected valid attenuation to pass, got: %v", err)
	}

	// 2. Wildcard parent permits any child scope
	if err := VerifyLocalAttenuation([]string{"*"}, []string{"admin:all", "fs:write"}, "*", "/data/*", "*", "write"); err != nil {
		t.Fatalf("expected wildcard parent to permit child scopes, got: %v", err)
	}

	// 3. Prefix matching (fs:* allows fs:read)
	if err := VerifyLocalAttenuation([]string{"fs:*"}, []string{"fs:read"}, "/app/*", "/app/sub/*", "exec", "exec"); err != nil {
		t.Fatalf("expected prefix wildcard to permit child scope, got: %v", err)
	}

	// 4. Escalation Blocked: scope outside parent boundary
	childScopesEsc := []string{"fs:read", "admin:all"}
	err := VerifyLocalAttenuation(parentScopes, childScopesEsc, "/workspace/*", "/workspace/src/*", "exec", "exec")
	if err == nil {
		t.Fatalf("expected privilege escalation error for broader scopes, got nil")
	}
	if !strings.Contains(err.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked in error, got: %v", err)
	}

	// 5. Escalation Blocked: resource broadened from /workspace/* to *
	errRes := VerifyLocalAttenuation(parentScopes, childScopesValid, "/workspace/*", "*", "exec", "exec")
	if errRes == nil || !strings.Contains(errRes.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked for broadened resource, got: %v", errRes)
	}

	// 6. Escalation Blocked: action broadened from read to write
	errAct := VerifyLocalAttenuation(parentScopes, childScopesValid, "/workspace/*", "/workspace/src/*", "read", "write")
	if errAct == nil || !strings.Contains(errAct.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked for broadened action, got: %v", errAct)
	}
}

func TestDelegateMint_SuccessAndEscalation(t *testing.T) {
	// Mock Control Plane HTTP server
	mockCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/grants/delegate" {
			http.NotFound(w, r)
			return
		}

		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		requestedScopes, _ := req["requested_scopes"].([]any)
		for _, s := range requestedScopes {
			if s == "admin:all" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":   "PrivilegeEscalationBlocked",
					"message": "child subagent requested scope admin:all outside parent boundary",
				})
				return
			}
		}

		resp := DelegateResponse{
			Token:         "mock-child-token-xyz",
			TokenType:     "Bearer",
			GrantID:       "grant-child-123",
			ParentGrantID: "grant-parent-001",
			RootAgentID:   "root-orchestrator",
			Lineage:       []string{"root-orchestrator", "subagent-worker"},
			LineageTree:   "root-orchestrator -> subagent-worker",
			ExpiresAt:     time.Now().Add(15 * time.Minute),
			TTLSecs:       900,
			Scopes:        []string{"fs:read"},
			SessionID:     "sess-child-test",
			Depth:         1,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockCP.Close()

	// 1. Success case
	err := RunDelegate([]string{
		"mint",
		"--server", mockCP.URL,
		"--parent-token", "valid-parent-token",
		"--child-agent", "subagent-worker",
		"--scopes", "fs:read",
		"--json",
	})
	if err != nil {
		t.Fatalf("expected delegate mint to succeed, got: %v", err)
	}

	// 2. Escalation blocked case
	errEsc := RunDelegate([]string{
		"mint",
		"--server", mockCP.URL,
		"--parent-token", "valid-parent-token",
		"--child-agent", "subagent-worker",
		"--scopes", "admin:all",
	})
	if errEsc == nil {
		t.Fatalf("expected privilege escalation to fail, got nil")
	}
	if !strings.Contains(errEsc.Error(), "PrivilegeEscalationBlocked") {
		t.Fatalf("expected PrivilegeEscalationBlocked in error, got: %v", errEsc)
	}
}

func TestDelegateStatus(t *testing.T) {
	// Without env vars
	os.Unsetenv("BAP_DELEGATION_LINEAGE")
	os.Unsetenv("BAP_LINEAGE_TREE")
	if err := RunDelegate([]string{"status"}); err != nil {
		t.Fatalf("expected status without env to succeed, got: %v", err)
	}

	// With env vars set
	os.Setenv("BAP_DELEGATION_LINEAGE", "root-orchestrator,subagent-1,worker-2")
	os.Setenv("BAP_LINEAGE_TREE", "root-orchestrator -> subagent-1 -> worker-2")
	os.Setenv("BAP_ROOT_AGENT_ID", "root-orchestrator")
	os.Setenv("BAP_PARENT_GRANT_ID", "grant-parent-100")
	os.Setenv("BAP_GRANT_ID", "grant-worker-200")
	defer func() {
		os.Unsetenv("BAP_DELEGATION_LINEAGE")
		os.Unsetenv("BAP_LINEAGE_TREE")
		os.Unsetenv("BAP_ROOT_AGENT_ID")
		os.Unsetenv("BAP_PARENT_GRANT_ID")
		os.Unsetenv("BAP_GRANT_ID")
	}()

	if err := RunDelegate([]string{"status"}); err != nil {
		t.Fatalf("expected status with env to succeed, got: %v", err)
	}
}

func TestExecutionReceiptAndAuditLineage(t *testing.T) {
	os.Setenv("BAP_DELEGATION_LINEAGE", "root-orchestrator,subagent-designer")
	os.Setenv("BAP_LINEAGE_TREE", "root-orchestrator -> subagent-designer")
	os.Setenv("BAP_ROOT_AGENT_ID", "root-orchestrator")
	os.Setenv("BAP_PARENT_GRANT_ID", "grant-root-111")
	os.Setenv("BAP_GRANT_ID", "grant-child-222")
	defer func() {
		os.Unsetenv("BAP_DELEGATION_LINEAGE")
		os.Unsetenv("BAP_LINEAGE_TREE")
		os.Unsetenv("BAP_ROOT_AGENT_ID")
		os.Unsetenv("BAP_PARENT_GRANT_ID")
		os.Unsetenv("BAP_GRANT_ID")
	}()

	ec := &execContext{
		startTime:    time.Now().UTC(),
		source:       "subagent-designer",
		sessionID:    "sess-test-lineage",
		decisionOnly: true,
	}

	receipt := generateExecutionReceipt(ec, "DECISION_ONLY", 0)
	if receipt == nil {
		t.Fatalf("expected receipt to be generated")
	}
	if receipt.LineageTree != "root-orchestrator -> subagent-designer" {
		t.Fatalf("expected LineageTree 'root-orchestrator -> subagent-designer', got %q", receipt.LineageTree)
	}
	if receipt.RootAgentID != "root-orchestrator" {
		t.Fatalf("expected RootAgentID 'root-orchestrator', got %q", receipt.RootAgentID)
	}
	if receipt.ParentGrantID != "grant-root-111" {
		t.Fatalf("expected ParentGrantID 'grant-root-111', got %q", receipt.ParentGrantID)
	}
	if receipt.GrantID != "grant-child-222" {
		t.Fatalf("expected GrantID 'grant-child-222', got %q", receipt.GrantID)
	}

	// Verify AuditEntry hash incorporates lineage
	entry1 := audit.AuditEntry{
		EventID:     "ev-1",
		SessionID:   "sess-test-lineage",
		Timestamp:   time.Now().UTC(),
		Executable:  "python",
		FullCommand: "python test.py",
		Decision:    "allow",
		LineageTree: "root-orchestrator -> subagent-designer",
		RootAgentID: "root-orchestrator",
		GrantID:     "grant-child-222",
	}
	entry2 := entry1
	entry2.LineageTree = "root-orchestrator -> other-subagent"

	hash1 := audit.ComputeEntryHash(entry1, "prev-hash-000")
	hash2 := audit.ComputeEntryHash(entry2, "prev-hash-000")
	if hash1 == hash2 {
		t.Fatalf("expected distinct hashes for different lineage trees, got identical hash %s", hash1)
	}
}
