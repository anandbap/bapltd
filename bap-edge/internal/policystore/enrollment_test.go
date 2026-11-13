package policystore

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func withCredential(t *testing.T, tok string) {
	t.Helper()
	old := CredentialProvider
	CredentialProvider = func() string { return tok }
	t.Cleanup(func() { CredentialProvider = old })
}

func pubB64(cp *fakeCP) string { return base64.StdEncoding.EncodeToString(cp.pub) }

// Enrollment (OTC/OIDC) hands out the key and asset; the first authenticated sync then verifies
// against them with no first-contact step and no hardware id from the request body involved.
func TestEnrollmentPinnedKeyAndAssetVerifyAuthenticatedSync(t *testing.T) {
	cp := newFakeCP(t)
	cp.enrolledAsset = "asset-enrolled"
	s := New(t.TempDir()) // no SetAssetID: the asset must come from the pin
	if err := s.PinEnrollment(cp.keyID, pubB64(cp), "asset-enrolled"); err != nil {
		t.Fatal(err)
	}
	withCredential(t, cp.token)

	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); err != nil {
		t.Fatalf("authenticated sync against an enrollment-pinned store failed: %v", err)
	}
	if cp.lastAuth != "Bearer "+cp.token {
		t.Fatalf("sync must carry the enrollment credential, got %q", cp.lastAuth)
	}
	if _, _, st, err := s.Current(); err != nil || st.AssetID != "asset-enrolled" {
		t.Fatalf("state must be bound to the enrolled asset: %+v err=%v", st, err)
	}
}

func TestBundleForAnotherAssetIsRejectedWhenAssetCameFromEnrollment(t *testing.T) {
	cp := newFakeCP(t)
	s := New(t.TempDir())
	_ = s.PinEnrollment(cp.keyID, pubB64(cp), "asset-enrolled")
	if err := s.Accept(cp.bundleFor("asset-someone-else")); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("a bundle issued for another machine must be rejected, got %v", err)
	}
}

// A machine that pinned by first contact before enrollment binding existed upgrades to its
// enrolled asset on the first authenticated sync, but only for a bundle its pinned key signed.
func TestLegacyFirstContactPinUpgradesOnAuthenticatedSync(t *testing.T) {
	cp := newFakeCP(t)
	cp.enrolledAsset = "asset-enrolled"
	s := New(t.TempDir())

	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); err != nil { // anonymous: fleet bundle
		t.Fatalf("anonymous first sync: %v", err)
	}
	if pin, _ := s.LoadPin(); pin.AssetID != "" {
		t.Fatalf("anonymous first contact must pin no asset, got %q", pin.AssetID)
	}

	withCredential(t, cp.token)
	cp.version++
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); err != nil {
		t.Fatalf("authenticated sync after upgrade failed: %v", err)
	}
	if pin, _ := s.LoadPin(); pin.AssetID != "asset-enrolled" {
		t.Fatalf("pin must adopt the authenticated asset, got %q", pin.AssetID)
	}
	if _, _, _, err := s.Current(); err != nil {
		t.Fatalf("state must verify after the upgrade: %v", err)
	}
}

func TestLegacyUpgradeNeedsAKeyMatchingBundle(t *testing.T) {
	cp := newFakeCP(t)
	s := New(t.TempDir())
	_ = s.PinEnrollment(cp.keyID, pubB64(cp), "") // legacy-style pin: no asset
	withCredential(t, "any-token")

	rogue := newFakeCP(t)
	if err := s.Accept(rogue.bundleFor("asset-evil")); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("an attacker must not be able to choose the asset via the upgrade path: %v", err)
	}
	if pin, _ := s.LoadPin(); pin.AssetID != "" {
		t.Fatal("pin must be unchanged")
	}
}

// Re-enrolling (OTC or OIDC) is the one authenticated way to replace a pin: this is the
// recovery path after the control plane's key was lost.
func TestReEnrollmentReplacesPinAfterKeyLoss(t *testing.T) {
	old := newFakeCP(t)
	s := newManagedStore(t, old, "asset-A")
	fresh := newFakeCP(t) // the control plane lost its key and generated a new one

	if err := s.PinKey(fresh.keyID, pubB64(fresh), ""); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("silently accepting a new key would defeat pinning, got %v", err)
	}
	if err := s.PinEnrollment(fresh.keyID, pubB64(fresh), "asset-A"); err != nil {
		t.Fatalf("re-enrollment must be able to replace the pin: %v", err)
	}
	if err := s.Accept(fresh.bundleFor("asset-A")); err != nil {
		t.Fatalf("bundles from the re-enrolled key must verify: %v", err)
	}
}

func TestClientFollowsAuthorisedKeyRotationWithoutUserAction(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	oldKey := cp.keyID

	cp.rotate()
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); err != nil {
		t.Fatalf("client pinned to the old key must follow the signed rotation chain: %v", err)
	}
	pin, _ := s.LoadPin()
	if pin.KeyID != cp.keyID || pin.KeyID == oldKey {
		t.Fatalf("client must now trust the new key, pinned %s", pin.KeyID)
	}
	cp.rotate() // and a second rotation, from the new key
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	if _, _, _, err := s.Current(); err != nil {
		t.Fatalf("state must verify under the rotated key: %v", err)
	}
}

func TestRotationWithoutValidChainIsRejected(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")

	// A rogue server that simply swaps the key (no link signed by the pinned key).
	rogue := newFakeCP(t)
	rogue.version = 50
	if err := s.Accept(rogue.bundleFor("asset-A")); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("an unchained key change must be rejected, got %v", err)
	}
	// A forged chain signed by the wrong key.
	forged := rogue.bundleFor("asset-A")
	forged.KeyChain = []rotationLink{{OldKeyID: cp.keyID, NewKeyID: rogue.keyID, NewPublic: pubB64(rogue), Signature: base64.StdEncoding.EncodeToString([]byte("not a signature at all, sixty-four bytes long......................."))}}
	if err := s.Accept(forged); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("a forged rotation link must be rejected, got %v", err)
	}
	if pin, _ := s.LoadPin(); pin.KeyID != cp.keyID {
		t.Fatal("pin must be unchanged after rejected rotations")
	}
}
