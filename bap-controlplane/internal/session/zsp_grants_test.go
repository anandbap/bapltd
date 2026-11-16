package session

import (
	"path/filepath"
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

func TestZSPGrants_SQLitePersistenceAndQuery(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test-controlplane.db")

	store, err := NewStoreWithDB(dbPath)
	if err != nil {
		t.Fatalf("failed to create store with db: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	grant1 := &types.TaskGrant{
		GrantID:            "grant-151647-e8595829a241",
		EnvelopeID:         "env-123",
		SessionID:          "sess-test-01",
		PrincipalSVID:      "spiffe://bap.local/agent/claude",
		HumanOwner:         "User@desktop.local",
		AllowedActions:     []string{"git:add", "fs:write"},
		AllowedResources:   []string{"workspace://current/GEMINI.md"},
		RequestedActions:   []string{"git:add", "fs:write"},
		RequestedResources: []string{"workspace://current/GEMINI.md"},
		NarrowingApplied:   false,
		MaxUses:            1,
		RemainingUses:      0,
		IssuedAt:           now,
		ExpiresAt:          now.Add(5 * time.Minute),
		IsBurned:           true,
		BurnReason:         "consumed by git add GEMINI.md",
		DelegationType:     "automatic",
		ClientType:         "claude-code",
		ConsumedCmd:        "git add GEMINI.md",
		ReceiptID:          "prf-e85958",
	}

	if err := store.SaveZSPGrant(grant1); err != nil {
		t.Fatalf("SaveZSPGrant failed: %v", err)
	}

	// 1. Fetch by ID
	fetched, err := store.GetZSPGrant("grant-151647-e8595829a241")
	if err != nil {
		t.Fatalf("GetZSPGrant failed: %v", err)
	}
	if fetched.GrantID != grant1.GrantID {
		t.Errorf("expected grant ID %s, got: %s", grant1.GrantID, fetched.GrantID)
	}
	if fetched.ConsumedCmd != "git add GEMINI.md" {
		t.Errorf("expected ConsumedCmd 'git add GEMINI.md', got: %s", fetched.ConsumedCmd)
	}
	if !fetched.IsBurned {
		t.Errorf("expected IsBurned=true")
	}
	if len(fetched.AllowedActions) != 2 || fetched.AllowedActions[0] != "git:add" {
		t.Errorf("unexpected allowed actions: %v", fetched.AllowedActions)
	}

	// 2. List grants by session
	sessGrants, err := store.ListZSPGrants("sess-test-01", 10)
	if err != nil {
		t.Fatalf("ListZSPGrants failed: %v", err)
	}
	if len(sessGrants) != 1 {
		t.Fatalf("expected 1 grant for sess-test-01, got: %d", len(sessGrants))
	}

	// 3. List grants across all sessions
	allGrants, err := store.ListZSPGrants("", 10)
	if err != nil {
		t.Fatalf("ListZSPGrants all failed: %v", err)
	}
	if len(allGrants) != 1 {
		t.Fatalf("expected 1 grant total, got: %d", len(allGrants))
	}
}
