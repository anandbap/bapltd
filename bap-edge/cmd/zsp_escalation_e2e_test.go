package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bap-edge/internal/authz"
)

// End-to-end replay (BAP-925 / BAP-926 / BAP-930) of the Claude Code <-> BAP calls report.
// Every scenario drives the real CLI entrypoint (RunZSP) and the real hook decision path
// (evaluateWithBapedgeTool) against an isolated ZSP state directory.

func e2eEnv(t *testing.T) (zspDir string) {
	t.Helper()
	zspDir = t.TempDir()
	t.Setenv("BAP_ZSP_DIR", zspDir)
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	t.Setenv("BAP_ZSP", "enforce")
	t.Setenv("BAP_MODE", "enforce")
	t.Setenv("BAP_IN_BROKER", "")
	t.Setenv("LTD_SOURCE", "")

	// Make stdin a pipe so the interactive challenge can never be answered by the test runner's terminal.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig; _ = r.Close() })
	return zspDir
}

// actAsHumanOperator removes every agent-identifying environment variable (this test process itself
// runs under an agent, which BAP correctly detects) so operator-only commands can be exercised.
func actAsHumanOperator(t *testing.T) {
	t.Helper()
	keep := map[string]bool{"BAP_ZSP_DIR": true, "BAP_STATE_DIR": true, "BAP_ZSP": true, "BAP_MODE": true}
	prefixes := []string{"BAP_", "LTD_", "CLAUDE", "ANTHROPIC", "ANTIGRAVITY", "AGY_", "GEMINI", "COPILOT",
		"GITHUB_COPILOT", "VSCODE_COPILOT", "CODEX", "OPENAI_CODEX", "OPENCODE", "CURSOR_AGENT", "AI_AGENT"}
	for _, kv := range os.Environ() {
		name := strings.SplitN(kv, "=", 2)[0]
		if keep[name] {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(strings.ToUpper(name), p) {
				val := os.Getenv(name)
				_ = os.Unsetenv(name)
				n, v := name, val
				t.Cleanup(func() { _ = os.Setenv(n, v) })
				break
			}
		}
	}
}

func authorize(sess string, extra ...string) error {
	args := append([]string{"authorize", "--session-id", sess, "--client", "claude-code", "--goal", "e2e"}, extra...)
	return RunZSP(args)
}

func TestE2E_AgentCannotSelfMintInterpreterOrWidenBoundary(t *testing.T) {
	e2eEnv(t)
	sess := "sess-e2e-interp"

	// Report: sbcl was first blocked on resource, then the agent re-requested --resources system://local and got it.
	for _, tc := range [][]string{
		{"--actions", "cli:sbcl:exec", "--resources", "workspace://current"},
		{"--actions", "cli:sbcl:exec", "--resources", "system://local"},
		{"--actions", "cli:python:exec", "--resources", "workspace://current"},
		{"--actions", "cli:vbc:exec", "--resources", "system://local"},
		{"--actions", "git:status", "--resources", "system://local"},
	} {
		err := authorize(sess, append(tc, "--max-uses", "1")...)
		if !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
			t.Errorf("%v: expected human-approval requirement, got %v", tc, err)
		}
	}

	// And with no grant the hook must refuse the actual execution.
	for _, c := range []string{"sbcl --version", "vbc /?", "python a11.py"} {
		if resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", c, ""); resp.Allowed {
			t.Errorf("%q must not execute without a grant", c)
		}
	}
}

func TestE2E_BroadRepoWildcardIsReadOnlyAndPushStaysBlocked(t *testing.T) {
	e2eEnv(t)
	sess := "sess-e2e-wild"

	if err := authorize(sess, "--actions", "repo:*", "--resources", "workspace://current/**", "--max-uses", "10"); err != nil {
		t.Fatalf("repo:* should be narrowed, got %v", err)
	}
	grants, err := authz.ListSessionZSPStatus(authz.ResolveZSPDir(), sess, "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants.ActiveGrants) == 0 {
		t.Fatal("expected an active narrowed grant")
	}
	for _, g := range grants.ActiveGrants {
		for _, a := range g.AllowedActions {
			if strings.Contains(a, "push") || strings.Contains(a, "write") {
				t.Fatalf("broad wildcard leaked a mutating action: %v", g.AllowedActions)
			}
		}
	}
	if resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", "git push", ""); resp.Allowed {
		t.Fatal("git push must stay blocked after a broad repo:* request")
	}
	// Report: "git:* / admin:*" style wildcards.
	for _, w := range []string{"*", "cli:*", "fs:*", "git:*"} {
		if err := authorize(sess, "--actions", w); err == nil {
			t.Errorf("wildcard %q must be rejected", w)
		}
	}
}

func TestE2E_ZeroFrictionForLegitimateWork(t *testing.T) {
	e2eEnv(t)
	sess := "sess-e2e-ok"
	if err := authorize(sess, "--actions", "git:status,git:log", "--resources", "workspace://current", "--max-uses", "2"); err != nil {
		t.Fatalf("read-only workspace work must be auto-approved: %v", err)
	}
	if resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", "git status --short", ""); !resp.Allowed {
		t.Fatalf("git status must execute under its grant, got %q", resp.Reason)
	}
	// Report: whoami after a git:status grant stayed blocked (least privilege).
	if resp := evaluateWithBapedgeTool(sess, "claude-code", "PowerShell", "whoami", ""); resp.Allowed {
		t.Fatal("whoami must stay outside a git:status grant")
	}
}

func TestE2E_HumanApprovalCannotBeScriptedOrSpoofed(t *testing.T) {
	e2eEnv(t)
	sess := "sess-e2e-oob"

	// Outside a broker with no real terminal, --oob-approve alone must NOT mint (it did before BAP-926).
	for _, acts := range []string{"policy:write,grant:elevate", "cli:python:exec"} {
		err := authorize(sess, "--actions", acts, "--oob-approve")
		if !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
			t.Errorf("--oob-approve without a terminal challenge must be refused for %s, got %v", acts, err)
		}
	}

	// Inside the agent broker the flag is refused outright.
	t.Setenv("BAP_IN_BROKER", "1")
	if err := authorize(sess, "--actions", "cli:python:exec", "--oob-approve"); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
		t.Errorf("--oob-approve inside broker must be refused, got %v", err)
	}
	// policy-sign is a human action; refused for agents.
	if err := RunZSP([]string{"policy-sign", "--file", "x.json"}); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
		t.Errorf("policy-sign inside broker must be refused, got %v", err)
	}
}

func TestE2E_MintCapAndSignedPolicyOverride(t *testing.T) {
	zspDir := e2eEnv(t)
	actAsHumanOperator(t)
	sess := "sess-e2e-cap"

	// Human operator installs a signed policy with a tiny mint cap.
	src := filepath.Join(t.TempDir(), "policy.json")
	def, err := os.ReadFile(filepath.Join("..", "internal", "authz", "default_permission_policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	custom := strings.Replace(string(def), `"max_mints_per_session": 100`, `"max_mints_per_session": 3`, 1)
	if err := os.WriteFile(src, []byte(custom), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RunZSP([]string{"policy-sign", "--file", src}); err != nil {
		t.Fatalf("operator policy-sign failed: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := authorize(sess, "--actions", "git:status"); err != nil {
			t.Fatalf("mint %d should succeed: %v", i, err)
		}
	}
	if err := authorize(sess, "--actions", "git:status"); !errors.Is(err, authz.ErrMintCapExceeded) {
		t.Fatalf("4th mint must hit the cap, got %v", err)
	}

	// Tampering with the installed override is fail-closed: minting stops instead of reverting to defaults.
	target := filepath.Join(zspDir, "permission-policy.json")
	if err := os.WriteFile(target, []byte(strings.Replace(custom, `"max_mints_per_session": 3`, `"max_mints_per_session": 9999`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := authorize("sess-e2e-tamper", "--actions", "git:status"); !errors.Is(err, authz.ErrPolicySignature) {
		t.Fatalf("tampered policy must fail closed, got %v", err)
	}
}

// Developer productivity (BAP-932): `git add` and `git commit` with a heredoc message must be governed by
// ZSP like any other workspace write, never denied as a cross-folder write because of words in the message.
func TestE2E_GitAddAndCommitWithHeredocMessageAreNotBlocked(t *testing.T) {
	e2eEnv(t)
	sess := "sess-e2e-commit"
	cmd := "git add JIRA_STORIES.md docs/PERMISSION_POLICY.md bap-edge/cmd/zsp.go && git commit -F - <<'EOF'\n" +
		"Harden ZSP grant minting (BAP-925/926/930)\n\n" +
		"- Replace --oob-approve / y-N approval with a one-time-code challenge.\n" +
		"- Epic 46 (BAP-922..931); see ../notes and /etc/hosts.\n" +
		"EOF"

	// Without a grant the refusal must be the ZSP one (with an actionable suggestion), not policy1 / cross-folder.
	resp := evaluateWithBapedgeTool(sess, "claude-code", "Bash", cmd, "")
	if resp.Allowed {
		t.Fatal("commit must need a grant under ZSP")
	}
	if strings.Contains(resp.Reason, "policy1") || strings.Contains(strings.ToLower(resp.Suggestion), "cross-folder") {
		t.Fatalf("commit was misclassified as a cross-folder write: reason=%q suggestion=%q", resp.Reason, resp.Suggestion)
	}
	if !strings.Contains(resp.Reason, "ZeroStandingPrivilegeViolation") || !strings.Contains(resp.Suggestion, "git:commit:write") {
		t.Fatalf("expected a ZSP refusal suggesting git:commit:write, got reason=%q suggestion=%q", resp.Reason, resp.Suggestion)
	}

	// Auto-approved tier: no human needed to get a grant for workspace commits.
	if err := authorize(sess, "--actions", "git:commit:write", "--resources", "workspace://current", "--max-uses", "2"); err != nil {
		t.Fatalf("workspace git commit grant must be auto-approved: %v", err)
	}
	if resp := evaluateWithBapedgeTool(sess, "claude-code", "Bash", cmd, ""); !resp.Allowed {
		t.Fatalf("git add && git commit must run under its grant, got reason=%q suggestion=%q", resp.Reason, resp.Suggestion)
	}

	// Push stays protected, as intended.
	if err := authorize(sess, "--actions", "git:push:write"); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
		t.Fatalf("git push must still need human approval, got %v", err)
	}
}

func TestE2E_CredentialActionsAreNeverGrantable(t *testing.T) {
	e2eEnv(t)
	for _, a := range []string{"aws:secretsmanager:read", "github:cli:secret", "credential:access"} {
		if err := authorize("sess-e2e-cred", "--actions", a); !errors.Is(err, authz.ErrActionDenied) {
			t.Errorf("%s must be hard-denied, got %v", a, err)
		}
	}
}
