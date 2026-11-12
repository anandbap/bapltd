package authz

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/identity"
)

// Regression suite for BAP-925 / BAP-926: an autonomous agent must not be able to
// widen its own authority. Every case below reproduces a behavior observed in the
// Claude Code <-> BAP calls report (session sess-claude-d8c8d6e4...), where the agent
// self-minted interpreter grants, widened the resource boundary and obtained a push.

const escalationWorkspace = "workspace://current"

func mintAs(t *testing.T, dir, sess string, actions, resources []string) error {
	t.Helper()
	_, _, err := SubmitTaskEnvelope(dir, sess, "claude-code", "TASK_EXECUTION",
		"escalation regression", "escalation regression", actions, resources, "", 1, 300*time.Second)
	return err
}

func TestEscalation_InterpreterExecIsNotAutoMinted(t *testing.T) {
	for _, act := range []string{"cli:python:exec", "cli:sbcl:exec", "cli:vbc:exec", "dev:python:exec", "cli:powershell:exec"} {
		err := mintAs(t, t.TempDir(), "sess-interp", []string{act}, []string{escalationWorkspace})
		if !errors.Is(err, ErrHighRiskApprovalRequired) {
			t.Errorf("%s: expected human approval requirement, got %v", act, err)
		}
	}
}

func TestEscalation_ResourceWideningBeyondWorkspaceRequiresApproval(t *testing.T) {
	for _, res := range []string{"system://local", "file://C:/Users", "net://example.com", "workspace://currentevil", "C:\\Windows"} {
		err := mintAs(t, t.TempDir(), "sess-widen", []string{"git:status"}, []string{res})
		if !errors.Is(err, ErrHighRiskApprovalRequired) {
			t.Errorf("resource %q: expected human approval requirement, got %v", res, err)
		}
	}
}

// Root-style wildcard resources are narrowed to the workspace, never widened.
func TestEscalation_RootWildcardResourceNarrowsToWorkspace(t *testing.T) {
	grant, _, err := SubmitTaskEnvelope(t.TempDir(), "sess-root", "claude-code", "TASK_EXECUTION",
		"g", "g", []string{"git:status"}, []string{"/*"}, "", 1, 300*time.Second)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if len(grant.AllowedResources) != 1 || grant.AllowedResources[0] != escalationWorkspace || !grant.NarrowingApplied {
		t.Fatalf("expected narrowing to %s, got %v (narrowed=%v)", escalationWorkspace, grant.AllowedResources, grant.NarrowingApplied)
	}
}

// Human approval unlocks the approve tier for an explicitly requested wider boundary (and nothing else).
func TestEscalation_ApprovedWideningIsHonoredOnlyWithOOB(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := SubmitTaskEnvelopeWithDelegation(dir, "sess-oob", "claude-code", "TASK_EXECUTION", "g", "g",
		[]string{"cli:sbcl:exec"}, []string{"system://local"}, "", "human_interactive_oob", 1, 300*time.Second); err != nil {
		t.Fatalf("approved escalation should mint, got %v", err)
	}
}

func TestEscalation_WildcardNeverGrantsPush(t *testing.T) {
	grant, _, err := SubmitTaskEnvelope(t.TempDir(), "sess-wild", "claude-code", "TASK_EXECUTION",
		"broad", "broad", []string{"repo:*"}, []string{escalationWorkspace}, "", 5, 300*time.Second)
	if err != nil {
		t.Fatalf("repo:* should narrow to read-only, got error %v", err)
	}
	for _, a := range grant.AllowedActions {
		if strings.Contains(a, "push") || strings.Contains(a, "write") || a == "repo:*" {
			t.Fatalf("wildcard narrowing leaked a mutating action: %v", grant.AllowedActions)
		}
	}
	if !grant.NarrowingApplied {
		t.Fatalf("expected NarrowingApplied=true")
	}
}

func TestEscalation_OtherWildcardsRejected(t *testing.T) {
	for _, act := range []string{"*", "cli:*", "admin:*", "git:*", "net:*", "dev:*"} {
		if err := mintAs(t, t.TempDir(), "sess-wild2", []string{act}, []string{escalationWorkspace}); err == nil {
			t.Errorf("wildcard %q must be rejected, got nil", act)
		}
	}
}

// A broad but harmless ask is narrowed (ALLOWED-LIMITED), not refused: the demo and the cockpit rely on it.
func TestEscalation_BroadReadAsksAreNarrowedNotRefused(t *testing.T) {
	grant, _, err := SubmitTaskEnvelope(t.TempDir(), "sess-narrow", "claude-code", "TASK_EXECUTION",
		"prepare to build", "prepare to build", []string{"repo:*", "fs:*"}, []string{"repo:*"}, "", 10, 300*time.Second)
	if err != nil {
		t.Fatalf("repo:* + fs:* on repo:* must be narrowed, got %v", err)
	}
	if !grant.NarrowingApplied {
		t.Fatal("expected NarrowingApplied")
	}
	want := map[string]bool{"repo:read": true, "fs:read": true}
	if len(grant.AllowedActions) != 2 || !want[grant.AllowedActions[0]] || !want[grant.AllowedActions[1]] {
		t.Fatalf("expected [repo:read fs:read], got %v", grant.AllowedActions)
	}
	if len(grant.AllowedResources) != 1 || grant.AllowedResources[0] != escalationWorkspace {
		t.Fatalf("expected resource narrowed to %s, got %v", escalationWorkspace, grant.AllowedResources)
	}
}

func TestEscalation_GitPushAndDeleteRequireApproval(t *testing.T) {
	for _, act := range []string{"git:push:write", "git:push", "fs:file:delete", "git:clean:delete"} {
		err := mintAs(t, t.TempDir(), "sess-push", []string{act}, []string{escalationWorkspace})
		if !errors.Is(err, ErrHighRiskApprovalRequired) {
			t.Errorf("%s: expected approval requirement, got %v", act, err)
		}
	}
}

func TestEscalation_CredentialActionsAreHardDenied(t *testing.T) {
	for _, act := range []string{"aws:secretsmanager:read", "github:cli:secret", "credential:access"} {
		dir := t.TempDir()
		if err := mintAs(t, dir, "sess-cred", []string{act}, []string{escalationWorkspace}); err == nil {
			t.Errorf("%s: expected hard denial, got nil", act)
		}
		// A human approval must not unlock a hard-deny tier either.
		_, _, err := SubmitTaskEnvelopeWithDelegation(dir, "sess-cred", "claude-code", "TASK_EXECUTION",
			"g", "g", []string{act}, []string{escalationWorkspace}, "", "human_interactive_oob", 1, 300*time.Second)
		if err == nil {
			t.Errorf("%s: hard-deny tier must hold even with out-of-band approval", act)
		}
	}
}

func TestEscalation_MintCapPerSession(t *testing.T) {
	dir := t.TempDir()
	var capErr error
	for i := 0; i < 400; i++ {
		if err := mintAs(t, dir, "sess-cap", []string{"git:status"}, []string{escalationWorkspace}); err != nil {
			capErr = err
			break
		}
	}
	if capErr == nil {
		t.Fatal("expected a per-session mint cap to stop unbounded grant minting")
	}
}

func TestEscalation_CeilingClampsUsesAndTTL(t *testing.T) {
	grant, _, err := SubmitTaskEnvelope(t.TempDir(), "sess-clamp", "claude-code", "TASK_EXECUTION",
		"g", "g", []string{"git:status"}, []string{escalationWorkspace}, "", 1_000_000, 100*24*time.Hour)
	if err != nil {
		t.Fatalf("expected clamped grant, got error %v", err)
	}
	if grant.MaxUses > 1000 {
		t.Errorf("max uses not clamped to ceiling: %d", grant.MaxUses)
	}
	if time.Until(grant.ExpiresAt) > 2*time.Hour {
		t.Errorf("ttl not clamped to ceiling: %s", time.Until(grant.ExpiresAt))
	}
}

func TestEscalation_EmptySigningSecretFailsClosed(t *testing.T) {
	minter := identity.NewWorkstationIdentityMinter("test-ca-secret-key-32-bytes-long!", "bap.corp.local")
	engine := NewZSPEngine(minter, "")
	_, err := engine.AuthorizeTaskEnvelope(nil, 1, time.Minute)
	if err == nil {
		t.Fatal("nil envelope must be rejected")
	}
	if _, cErr := engine.ConsumeTaskGrant("grant-x", "git:status", escalationWorkspace, "git status", nil); cErr == nil {
		t.Fatal("engine with no signing secret must refuse to consume grants")
	}
	if fmt.Sprint(engine.signingSecretConfigured()) != "false" {
		t.Fatal("expected engine to report missing signing secret instead of using a hardcoded default")
	}
}

// Positive controls: legitimate read-only and build/test workflows must stay frictionless.
func TestEscalation_LegitimateWorkspaceWorkStaysAllowed(t *testing.T) {
	cases := [][]string{
		{"git:status", "git:log", "git:diff", "git:branch"},
		{"git:inspect:read"},
		{"fs:read", "fs:list", "fs:search"},
		{"fs:write"},
		{"dev:go:test", "dev:go:build", "dev:go:vet"},
		{"git:commit:write"},
	}
	for _, acts := range cases {
		if err := mintAs(t, t.TempDir(), "sess-ok", acts, []string{escalationWorkspace}); err != nil {
			t.Errorf("%v should be auto-approved inside the workspace, got %v", acts, err)
		}
	}
}
