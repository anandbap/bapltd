package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/authz"
)

// ZSP-REVIEW-01 hardening, end to end through the real hook decision path (evaluateWithBapedgeTool).
// The agent must not be able to NAME the files that decide what it may do, through any tool, and
// forging them by other means must not turn on approval-free operation.

func TestE2E_AgentCannotNameAuthorityStateThroughAnyTool(t *testing.T) {
	zsp := e2eEnv(t)
	sess := "sess-e2e-authority"
	if err := authorize(sess, "--actions", "fs:read,fs:file:write", "--resources", "workspace://current", "--max-uses", "20"); err != nil {
		t.Fatal(err)
	}

	secret := filepath.Join(zsp, "pepper.key")
	window := filepath.Join(zsp, "autoapprove.json")
	approvals := filepath.Join(zsp, "approvals")

	// Native tools, with a live read/write grant in hand.
	for _, tc := range []struct{ tool, path string }{
		{"Read", secret},
		{"Read", window},
		{"Grep", approvals},
		{"Glob", zsp},
		{"Write", window},
		{"Edit", filepath.Join(approvals, "req-deadbeef.json")},
	} {
		resp := evaluateWithBapedgeTool(sess, "claude-code", tc.tool, "", tc.path)
		if resp.Allowed || !strings.Contains(resp.Reason, "credential stores") {
			t.Errorf("%s %s must be refused as a protected store; allowed=%v reason=%q", tc.tool, tc.path, resp.Allowed, resp.Reason)
		}
	}

	// Shell commands that name the same files.
	for _, c := range []string{
		`Get-Content "` + secret + `"`,
		`type ` + window,
		`cat ` + filepath.ToSlash(secret),
		`dir ` + zsp,
		`Copy-Item ` + approvals + `\req-1.json x.json`,
	} {
		resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", c, "")
		if resp.Allowed || !strings.Contains(resp.Reason, "credential stores") {
			t.Errorf("%q must be refused; allowed=%v reason=%q", c, resp.Allowed, resp.Reason)
		}
	}
}

// Usability guard: BAP is not bricked. A developer's flow and the agent's request/inspection flow
// still work with the protection active.
func TestE2E_AuthorityProtectionDoesNotBreakNormalOperation(t *testing.T) {
	e2eEnv(t)
	sess := "sess-e2e-usable"

	if err := authorize(sess, "--actions", "fs:file:write", "--resources", "workspace://current", "--max-uses", "5"); err != nil {
		t.Fatalf("grant request must still work, got %v", err)
	}
	for _, c := range []string{"bapedge zsp status", "bapedge zsp approvals"} {
		resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", c, "")
		if strings.Contains(resp.Reason, "credential stores") {
			t.Errorf("%q must not be mistaken for a credential access: %q", c, resp.Reason)
		}
	}
	resp := evaluateWithBapedgeTool(sess, "claude-code", "Read", "", "README.md")
	if strings.Contains(resp.Reason, "credential stores") {
		t.Errorf("an ordinary workspace file must not be refused as a protected store: %q", resp.Reason)
	}
	// Request, human view of it, and agent-side inspection all use the Go APIs, not agent-named paths.
	raised, err := authz.RaisePendingApproval(authz.ResolveZSPDir(), authz.PendingApproval{
		SessionID: sess, ClientType: "claude-code", Mission: "TASK_EXECUTION", Goal: "usable",
		Actions: []string{"cli:python:exec"}, Resources: []string{"workspace://current"}, MaxUses: 1, TTLSeconds: 300, Reason: "test",
	})
	if err != nil || raised == nil {
		t.Fatalf("approval requests must still be raisable: %v", err)
	}
	if err := RunZSP([]string{"approvals"}); err != nil {
		t.Fatalf("listing approvals must still work: %v", err)
	}
}

// A hand-forged auto-approve window (what an agent with raw file write could try) is ignored: the
// signature is bound to the PEP secret the agent can no longer read.
func TestE2E_ForgedAutoApproveWindowIsIgnored(t *testing.T) {
	zsp := e2eEnv(t)
	forged := map[string]any{
		"enabled_at": time.Now().UTC(),
		"expires_at": time.Now().UTC().Add(time.Hour),
		"enabled_by": "developer",
		"signature":  strings.Repeat("0", 64),
	}
	raw, _ := json.Marshal(forged)
	if err := os.WriteFile(filepath.Join(zsp, "autoapprove.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if on, _, _ := authz.AutoApproveStatus(zsp); on {
		t.Fatal("a forged auto-approve record must never open the window")
	}
}

// Writing an approved status into a pending-request file must not mint or authorise anything: approval
// is only ever produced by the guarded decide path.
func TestE2E_TamperedApprovalFileDoesNotGrantAnything(t *testing.T) {
	zsp := e2eEnv(t)
	sess := "sess-e2e-tamper"
	p, err := authz.RaisePendingApproval(zsp, authz.PendingApproval{
		SessionID: sess, ClientType: "claude-code", Mission: "TASK_EXECUTION", Goal: "tamper",
		Actions: []string{"cli:python:exec"}, Resources: []string{"workspace://current"}, MaxUses: 1, TTLSeconds: 300, Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(zsp, "approvals", p.ID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["status"], m["grant_id"] = "approved", "grant-forged"
	forged, _ := json.Marshal(m)
	if err := os.WriteFile(path, forged, 0o600); err != nil {
		t.Fatal(err)
	}

	if resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", "python a.py", ""); resp.Allowed {
		t.Fatal("a tampered approval file must not allow an interpreter to run")
	}
	status, err := authz.ListSessionZSPStatus(zsp, sess, "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range status.ActiveGrants {
		if g.GrantID == "grant-forged" {
			t.Fatal("a forged approval must never appear as an active grant")
		}
	}
}
