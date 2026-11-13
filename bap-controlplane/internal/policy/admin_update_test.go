package policy

import "testing"

func TestFreezeAndUnfreezeAreSignedVersionedUpdates(t *testing.T) {
	key := []byte("test-signing-key")
	store := NewStoreWithKey("permit(principal, action, resource);", "", key)
	previous := store.GetBundle()
	for _, frozen := range []bool{true, false} {
		store.SetKillSwitch(frozen)
		current := store.GetBundle()
		if current.Version <= previous.Version || !VerifySignature(current.Version, current.Digest, current.KillSwitch, current.Signature, key) {
			t.Fatalf("freeze change not signed/versioned: %+v", current)
		}
		if _, ok := store.UpdateIfVersion(previous.PolicyCedar, previous.SchemaJSON, previous.KillSwitch, previous.Version); ok {
			t.Fatal("stale editor overwrote a freeze decision")
		}
		if !frozen && store.Sync(SyncRequest{InstalledVersion: previous.Version, InstalledDigest: previous.Digest}).Directive != DirectiveUpdateRequired {
			t.Fatal("unfreeze was invisible to an edge with the previous policy")
		}
		previous = current
	}
}
