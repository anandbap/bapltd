package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/pkg/types"
)

func TestZSP_PlaybackAndAllSessions(t *testing.T) {
	tempBase := t.TempDir()
	zspDir := filepath.Join(tempBase, "zsp")
	t.Setenv("BAP_ZSP_DIR", zspDir)
	t.Setenv("BAP_STATE_DIR", tempBase)

	sessID := "sess-playback-01"
	grantsDir := filepath.Join(zspDir, "grants", sessID)
	if err := os.MkdirAll(grantsDir, 0700); err != nil {
		t.Fatalf("failed to create grants dir: %v", err)
	}

	now := time.Now().UTC()
	g1 := types.TaskGrant{
		GrantID:          "grant-151647-e8595829a241",
		EnvelopeID:       "env-01",
		SessionID:        sessID,
		PrincipalSVID:    "spiffe://bap.local/agent/claude",
		HumanOwner:       "developer@example.com",
		AllowedActions:   []string{"git:add"},
		AllowedResources: []string{"workspace://current/GEMINI.md"},
		MaxUses:          1,
		RemainingUses:    0,
		IssuedAt:         now.Add(-2 * time.Minute),
		ExpiresAt:        now.Add(3 * time.Minute),
		IsBurned:         true,
		BurnReason:       "Consumed by git add",
		DelegationType:   "automatic",
		ClientType:       "claude-code",
		ConsumedCmd:      "git add GEMINI.md",
		ReceiptID:        "prf-123456",
	}

	g2 := types.TaskGrant{
		GrantID:          "grant-152000-a1b2c3d4e5f6",
		EnvelopeID:       "env-02",
		SessionID:        sessID,
		PrincipalSVID:    "spiffe://bap.local/agent/claude",
		HumanOwner:       "developer@example.com",
		AllowedActions:   []string{"network:egress"},
		AllowedResources: []string{"api.external.bank.com"},
		MaxUses:          1,
		RemainingUses:    1,
		IssuedAt:         now,
		ExpiresAt:        now.Add(5 * time.Minute),
		IsBurned:         false,
		DelegationType:   "manual_hitl_oob",
		ClientType:       "claude-code",
	}

	for _, g := range []types.TaskGrant{g1, g2} {
		data, _ := json.MarshalIndent(g, "", "  ")
		_ = os.WriteFile(filepath.Join(grantsDir, g.GrantID+".json"), data, 0600)
	}

	// 1. Test CollectAllWorkstationGrants
	allG, err := authz.CollectAllWorkstationGrants(zspDir)
	if err != nil {
		t.Fatalf("CollectAllWorkstationGrants failed: %v", err)
	}
	if len(allG) != 2 {
		t.Fatalf("expected 2 grants, got: %d", len(allG))
	}

	// 2. Test RunZSP status --all-sessions
	if err := RunZSP([]string{"status", "--all-sessions"}); err != nil {
		t.Fatalf("RunZSP status --all-sessions failed: %v", err)
	}

	// 3. Test RunZSP playback
	if err := RunZSP([]string{"playback"}); err != nil {
		t.Fatalf("RunZSP playback failed: %v", err)
	}
}
