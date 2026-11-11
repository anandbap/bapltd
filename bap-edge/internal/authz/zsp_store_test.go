package authz

import (
	"errors"
	"os"
	"path/filepath"
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
