package policy

import (
	"testing"
)

func TestPolicyStore_Sync(t *testing.T) {
	cedar := "permit(principal, action, resource);"
	schema := "{}"
	store := NewStore(cedar, schema)

	b := store.GetBundle()
	if b.Version != 1 {
		t.Fatalf("expected version 1, got %d", b.Version)
	}
	if b.Digest == "" {
		t.Fatalf("expected non-empty digest")
	}

	// 1. Unsynchronized edge asks for sync -> UPDATE_REQUIRED
	resp := store.Sync(SyncRequest{
		AgentID:          "agent-1",
		InstalledVersion: 0,
		InstalledDigest:  "",
	})
	if resp.Directive != DirectiveUpdateRequired || resp.Bundle == nil {
		t.Fatalf("expected UPDATE_REQUIRED, got %v", resp.Directive)
	}

	// 2. Synchronized edge asks for sync -> CURRENT
	resp = store.Sync(SyncRequest{
		AgentID:          "agent-1",
		InstalledVersion: b.Version,
		InstalledDigest:  b.Digest,
	})
	if resp.Directive != DirectiveCurrent {
		t.Fatalf("expected CURRENT, got %v", resp.Directive)
	}

	// 3. Central policy update occurs
	b2 := store.Update("permit(principal, action, resource) when { true };", schema, false)
	if b2.Version != 2 {
		t.Fatalf("expected version 2, got %d", b2.Version)
	}

	// Edge with old version now gets UPDATE_REQUIRED
	resp = store.Sync(SyncRequest{
		AgentID:          "agent-1",
		InstalledVersion: b.Version,
		InstalledDigest:  b.Digest,
	})
	if resp.Directive != DirectiveUpdateRequired {
		t.Fatalf("expected UPDATE_REQUIRED after update, got %v", resp.Directive)
	}

	// 4. Central emergency kill switch is enabled
	store.SetKillSwitch(true)
	resp = store.Sync(SyncRequest{
		AgentID:          "agent-1",
		InstalledVersion: b2.Version,
		InstalledDigest:  b2.Digest,
	})
	if resp.Directive != DirectiveKillSwitch {
		t.Fatalf("expected KILL_SWITCH, got %v", resp.Directive)
	}
}

func TestPolicyStore_BundleSigning(t *testing.T) {
	cedar := "permit(principal, action, resource);"
	schema := "{}"
	key := []byte("test-controlplane-signing-key-32b")
	store := NewStoreWithKey(cedar, schema, key)

	b := store.GetBundle()
	if b.Signature == "" {
		t.Fatalf("expected signed bundle, got empty signature")
	}

	if !VerifySignature(b.Version, b.Digest, b.KillSwitch, b.Signature, key) {
		t.Fatalf("signature verification failed for valid bundle")
	}

	if VerifySignature(b.Version, b.Digest, b.KillSwitch, "forged-sig", key) {
		t.Fatalf("signature verification should have failed for forged signature")
	}

	// Update bumps version and generates new signature
	b2 := store.Update("permit(principal, action, resource) when { false };", schema, false)
	if b2.Version != 2 {
		t.Fatalf("expected version 2, got %d", b2.Version)
	}
	if b2.Signature == "" || b2.Signature == b.Signature {
		t.Fatalf("expected unique signature for version 2")
	}
	if !VerifySignature(b2.Version, b2.Digest, b2.KillSwitch, b2.Signature, key) {
		t.Fatalf("signature verification failed for version 2 bundle")
	}
}
