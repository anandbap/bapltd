package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/internal/state"
	"bap-edge/pkg/types"
)

func TestZSPSessionGrantLinking_CapturesRequestingSession(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("BAP_STATE_DIR", tmpDir)
	t.Setenv("BAP_ZSP_DIR", filepath.Join(tmpDir, "zsp"))
	state.ResetForTesting()

	canonicalSession := "sess-antigravity-cli-51e4ed8f"
	childExecSession := "sess-antigravity-39656"

	// 1. Submit a task envelope where child session is target, but requesting session is canonical
	grant, env, err := authz.SubmitTaskEnvelopeWithDelegation(
		filepath.Join(tmpDir, "zsp"),
		childExecSession,
		"antigravity",
		"TASK_EXECUTION",
		"Inspect repository files",
		"Inspect repository files",
		[]string{"git:status", "git:inspect:read"},
		[]string{"workspace://current"},
		"User@desktop.local",
		"human_interactive_prompt",
		2,
		300*time.Second,
		canonicalSession,
	)
	if err != nil {
		t.Fatalf("SubmitTaskEnvelopeWithDelegation failed: %v", err)
	}

	if env.RequestingSessionID != canonicalSession {
		t.Errorf("expected Envelope.RequestingSessionID %q, got %q", canonicalSession, env.RequestingSessionID)
	}
	if grant.RequestingSessionID != canonicalSession {
		t.Errorf("expected Grant.RequestingSessionID %q, got %q", canonicalSession, grant.RequestingSessionID)
	}
	if grant.SessionID != childExecSession {
		t.Errorf("expected Grant.SessionID %q, got %q", childExecSession, grant.SessionID)
	}

	// 2. Verify grant is persisted in BOTH sessions' grant directories
	childDir := filepath.Join(tmpDir, "zsp", "grants", childExecSession)
	canonicalDir := filepath.Join(tmpDir, "zsp", "grants", canonicalSession)

	childFile := filepath.Join(childDir, grant.GrantID+".json")
	if _, err := os.Stat(childFile); err != nil {
		t.Fatalf("expected grant file in child session dir: %v", err)
	}

	canonicalFile := filepath.Join(canonicalDir, grant.GrantID+".json")
	if _, err := os.Stat(canonicalFile); err != nil {
		t.Fatalf("expected grant file linked in canonical session dir: %v", err)
	}

	// 3. Verify that evaluating under the CANONICAL session finds and consumes the grant
	svid, matched, proof, err := authz.VerifyOrConsumeSessionZSPChecks(
		filepath.Join(tmpDir, "zsp"),
		canonicalSession,
		"antigravity",
		[]authz.ZSPActionCheck{{Action: "git:status", CanonicalResource: "workspace://current"}},
		"git status",
		authz.GetWorkspaceRoot(),
		true,
		[]string{"antigravity", "bapedge"},
	)
	if err != nil {
		t.Fatalf("expected canonical session to consume linked grant, got error: %v", err)
	}
	if matched.GrantID != grant.GrantID {
		t.Errorf("expected matched grant %q, got %q", grant.GrantID, matched.GrantID)
	}
	if proof == nil {
		t.Errorf("expected non-nil lineage proof")
	}
	_ = svid

	// 4. Verify that consumption was synchronized across both session grant files
	for _, f := range []string{childFile, canonicalFile} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("failed to read %s: %v", f, err)
		}
		var updated types.TaskGrant
		if err := json.Unmarshal(data, &updated); err != nil {
			t.Fatalf("failed to unmarshal %s: %v", f, err)
		}
		if updated.RemainingUses != 1 {
			t.Errorf("file %s remaining_uses expected 1, got %d", f, updated.RemainingUses)
		}
	}
}
