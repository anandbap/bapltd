package authz

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPersistentZSPZeroStandingPrivilegesAndEnvelopeFlow(t *testing.T) {
	zspDir := t.TempDir()
	ws := t.TempDir()
	sessionID := "sess-test-zsp-flow"

	// 1. Initialize cryptographic principal: starting permission set MUST be 0 (fail closed)
	svid, _, _, _, err := EnsureSessionPrincipal(zspDir, sessionID, "claude-code")
	if err != nil {
		t.Fatalf("EnsureSessionPrincipal failed: %v", err)
	}
	if svid.Subject == "" || svid.PublicKeyHex == "" {
		t.Fatalf("expected non-empty SVID subject & Ed25519 public key, got %+v", svid)
	}

	// Attempt 'whoami' without submitting a 4-tuple envelope
	actWho, resWho, escWho := ResolveZSPActionAndResource("whoami", "whoami", "", "", "", ws)
	_, _, _, err = VerifyOrConsumeSessionZSP(zspDir, sessionID, "claude-code", actWho, resWho, "whoami", ws, escWho, false, nil)
	if !errors.Is(err, ErrZeroStandingPrivilegeViolation) {
		t.Fatalf("expected ErrZeroStandingPrivilegeViolation for ungranted 'whoami', got: %v", err)
	}

	// Attempt 'Get-ChildItem -Force \' -> must detect filesystem root escape & fail ZSP
	actGCI, resGCI, escGCI := ResolveZSPActionAndResource(`Get-ChildItem -Force \`, "get-childitem", `-Force \`, "", "", ws)
	if !escGCI {
		t.Fatalf("expected Get-ChildItem -Force \\ to flag workspace/root escape")
	}
	_, _, _, err = VerifyOrConsumeSessionZSP(zspDir, sessionID, "claude-code", actGCI, resGCI, `Get-ChildItem -Force \`, ws, escGCI, false, nil)
	if !errors.Is(err, ErrZeroStandingPrivilegeViolation) {
		t.Fatalf("expected ErrZeroStandingPrivilegeViolation for Get-ChildItem root, got: %v", err)
	}

	// 2. Submit signed 4-tuple envelope for git:status only (MaxUses = 1)
	grant, env, err := SubmitTaskEnvelope(
		zspDir, sessionID, "claude-code",
		"CODE_INSPECTION", "Inspect current git status", "Check git status",
		[]string{"git:status"}, []string{"workspace://current"},
		"dev@corp.com", 1, 300*time.Second,
	)
	if err != nil || grant == nil || env == nil {
		t.Fatalf("SubmitTaskEnvelope failed: %v", err)
	}

	// Verify dry-run check does NOT burn the single-use grant
	actGit, resGit, escGit := ResolveZSPActionAndResource("git status", "git", "status", "", "", ws)
	_, checked, _, err := VerifyOrConsumeSessionZSP(zspDir, sessionID, "claude-code", actGit, resGit, "git status", ws, escGit, false, nil)
	if err != nil || checked.RemainingUses != 1 {
		t.Fatalf("expected dry-run check to pass with 1 use remaining, got err=%v grant=%+v", err, checked)
	}

	// Grant scoped to git:status on workspace://current MUST STILL DENY whoami and root listing
	_, _, _, err = VerifyOrConsumeSessionZSP(zspDir, sessionID, "claude-code", actWho, resWho, "whoami", ws, escWho, true, nil)
	if err == nil {
		t.Fatalf("expected ungranted whoami to be denied under git:status grant")
	}
	_, _, _, err = VerifyOrConsumeSessionZSP(zspDir, sessionID, "claude-code", actGCI, resGCI, `Get-ChildItem -Force \`, ws, escGCI, true, nil)
	if err == nil {
		t.Fatalf("expected root escape Get-ChildItem -Force \\ to be denied under workspace://current git:status grant")
	}

	// Consume single-use grant cleanly on 'git status'
	_, usedGrant, proof, err := VerifyOrConsumeSessionZSP(zspDir, sessionID, "claude-code", actGit, resGit, "git status", ws, escGit, true, []string{"claude", "bapedge"})
	if err != nil {
		t.Fatalf("expected VerifyOrConsumeSessionZSP to succeed on git status: %v", err)
	}
	if !usedGrant.IsBurned || usedGrant.RemainingUses != 0 {
		t.Fatalf("expected grant to be burned after 1 use, got %+v", usedGrant)
	}
	if proof == nil || proof.GrantID != grant.GrantID || proof.LedgerSignature == "" {
		t.Fatalf("expected valid signed AuditLineageProof, got %+v", proof)
	}
	if _, err := os.Stat(filepath.Join(zspDir, "lineage.jsonl")); err != nil {
		t.Fatalf("expected lineage.jsonl to be written: %v", err)
	}

	// Reusing burned grant fails closed cleanly
	_, _, _, err = VerifyOrConsumeSessionZSP(zspDir, sessionID, "claude-code", actGit, resGit, "git status", ws, escGit, true, nil)
	if !errors.Is(err, ErrGrantBurned) {
		t.Fatalf("expected ErrGrantBurned on replay after single use, got: %v", err)
	}
}

func TestAuthorizerBlocksFilesystemRootListing(t *testing.T) {
	a, err := NewAuthorizer("../../policy.cedar")
	if err != nil {
		t.Fatalf("NewAuthorizer failed: %v", err)
	}
	ws := t.TempDir()

	for _, cmd := range []string{`Get-ChildItem -Force \`, `ls /`, `dir C:\`} {
		allowed, reason, evalErr := a.EvaluateWithWorkspace("", cmd, "", ws)
		if evalErr != nil {
			t.Fatalf("EvaluateWithWorkspace(%q) err: %v", cmd, evalErr)
		}
		if allowed {
			t.Fatalf("expected root enumeration %q to be denied by Authorizer, but was allowed", cmd)
		}
		if reason == "" {
			t.Fatalf("expected denial reason for %q", cmd)
		}
	}
}

func TestIsZSPControlCommandQuotedOperatorsAndChaining(t *testing.T) {
	allowed := []string{
		`bapedge zsp status`,
		`bapedge zsp authorize --session-id s1 --mission CODE_INSPECTION --goal "Inspect git branch & recent commits" --actions "git:inspect:read" --resources workspace://current`,
		`bapedge zsp authorize --session-id s1 --mission CODE_INSPECTION --goal 'Branch; log & diff' --actions git:inspect:read --resources workspace://current`,
		`& "C:\Program Files\BAP\bapedge.exe" zsp authorize --session-id s1 --mission CODE_INSPECTION --goal "Inspect git" --actions "git:status" --resources workspace://current`,
	}
	for _, cmd := range allowed {
		if !IsZSPControlCommand(cmd) {
			t.Errorf("IsZSPControlCommand(%q) = false, want true", cmd)
		}
	}

	blocked := []string{
		`bapedge zsp authorize --session-id s1 && git status`,
		`bapedge zsp status; whoami`,
		`bapedge zsp status | cat`,
		`bapedge zsp status > out.txt`,
		`bapedge zsp authorize --goal "unclosed && whoami`,
		`bapedge zsp authorize --goal "$(whoami)"`,
	}
	for _, cmd := range blocked {
		if IsZSPControlCommand(cmd) {
			t.Errorf("IsZSPControlCommand(%q) = true, want false", cmd)
		}
	}
}

func TestResolveZSPCommandChecksAndCompoundVerification(t *testing.T) {
	ws := t.TempDir()
	cmd := "git status --short --branch; git log --oneline -n 10"
	checks := ResolveZSPCommandChecks(cmd, "git", "status --short --branch; git log --oneline -n 10", "", "", ws)
	if got := SummarizeZSPActions(checks); got != "git:status,git:log" {
		t.Fatalf("SummarizeZSPActions(%q) = %q, want %q", cmd, got, "git:status,git:log")
	}
	if len(checks) != 2 {
		t.Fatalf("expected 2 atomic checks for compound command, got %d (%+v)", len(checks), checks)
	}

	sugg := FormatZSPAgentSuggestion("spiffe://bap.local/agent/claude-code", "sess-1", cmd, "git:status,git:log", len(checks))
	if !strings.Contains(sugg, `--actions "git:status,git:log"`) || !strings.Contains(sugg, `--max-uses 2`) {
		t.Fatalf("unexpected suggestion: %s", sugg)
	}

	zspDir := t.TempDir()
	_, _, err := SubmitTaskEnvelope(zspDir, "sess-status-only", "claude-code", "CODE_INSPECTION", "git status", "check status", []string{"git:status"}, []string{"workspace://current"}, "", 2, 0)
	if err != nil {
		t.Fatalf("SubmitTaskEnvelope failed: %v", err)
	}
	if _, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, "sess-status-only", "claude-code", checks, cmd, ws, true, nil); err == nil {
		t.Fatal("expected compound command requiring git:status and git:log to fail against git:status-only grant")
	}

	_, _, err = SubmitTaskEnvelope(zspDir, "sess-both", "claude-code", "CODE_INSPECTION", "git status & log", "inspect branch and commits", []string{"git:status", "git:log"}, []string{"workspace://current"}, "", 1, 0)
	if err != nil {
		t.Fatalf("SubmitTaskEnvelope (both) failed: %v", err)
	}
	if _, grant, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, "sess-both", "claude-code", checks, cmd, ws, true, nil); err != nil {
		t.Fatalf("expected compound command to succeed and consume once with matching grant, got: %v", err)
	} else if grant == nil || !grant.IsBurned || grant.RemainingUses != 0 {
		t.Fatalf("expected 1-use grant to burn after compound execution, got: %+v", grant)
	}
}
