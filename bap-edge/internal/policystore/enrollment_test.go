package policystore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	if err := s.PinEnrollment(cp.keyID, pubB64(cp), "asset-enrolled", cp.srv.URL); err != nil {
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
	_ = s.PinEnrollment(cp.keyID, pubB64(cp), "asset-enrolled", cp.srv.URL)
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
	_ = s.PinEnrollment(cp.keyID, pubB64(cp), "", cp.srv.URL) // legacy-style pin: no asset
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

	if err := s.PinKey(fresh.keyID, pubB64(fresh), "", ""); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("silently accepting a new key would defeat pinning, got %v", err)
	}
	// Same control plane (its URL), new key: the key-loss recovery path.
	if err := s.PinEnrollment(fresh.keyID, pubB64(fresh), "asset-A", old.srv.URL); err != nil {
		t.Fatalf("re-enrollment must be able to replace the pin: %v", err)
	}
	if err := s.Accept(fresh.bundleFor("asset-A")); err != nil {
		t.Fatalf("bundles from the re-enrolled key must verify: %v", err)
	}
}

// A machine enrolled with control plane A must never take policy from, or be broken by, a
// different control plane (a local test instance on a developer workstation, a look-alike).
func TestOtherControlPlaneIsIgnoredAndCannotBreakTheMachine(t *testing.T) {
	real := newFakeCP(t)
	s := newManagedStore(t, real, "asset-A") // first contact pins `real` and its URL
	before, _, _, err := s.Current()
	if err != nil || before == "" {
		t.Fatalf("baseline: %v", err)
	}

	other := newFakeCP(t) // different key, different URL (e.g. the pilot's throwaway control plane)
	other.readEx = false
	other.version = 99
	_, fallback, err := s.SyncWithServer(other.srv.URL, "", 2*time.Second)
	if err != nil || !fallback {
		t.Fatalf("a foreign control plane must be skipped as if offline: fallback=%v err=%v", fallback, err)
	}
	if other.lastAuth != "" {
		t.Fatal("a foreign control plane must never even receive a request (no credential leak)")
	}
	_, _, st, err := s.Current()
	if err != nil || st.Version != 1 || !st.ZSPReadExempt {
		t.Fatalf("enrolled rules must be unchanged and still verify: %+v err=%v", st, err)
	}
	if pin, _ := s.LoadPin(); pin.KeyID != real.keyID {
		t.Fatal("pin must be unchanged")
	}
}

func TestForeignControlPlaneDoesNotMaskTampering(t *testing.T) {
	real := newFakeCP(t)
	s := newManagedStore(t, real, "asset-A")
	st, _ := s.LoadState()
	st.ZSPReadExempt = !st.ZSPReadExempt
	data, _ := json.Marshal(st)
	_ = os.WriteFile(filepath.Join(s.Directory(), "policy-signed.json"), data, 0600)

	other := newFakeCP(t)
	if _, _, err := s.SyncWithServer(other.srv.URL, "", 2*time.Second); err == nil {
		t.Fatal("tampered rules must still fail closed even when only a foreign control plane is reachable")
	}
}

func TestLegacyPinWithoutURLAdoptsItOnVerifiedSync(t *testing.T) {
	cp := newFakeCP(t)
	s := New(t.TempDir())
	s.SetAssetID("asset-A")
	_ = s.PinEnrollment(cp.keyID, pubB64(cp), "asset-A", "") // pinned before URLs were recorded
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if pin, _ := s.LoadPin(); pin.ServerURL == "" {
		t.Fatal("a verified sync must record the control plane URL on a legacy pin")
	}
	other := newFakeCP(t)
	if _, fallback, err := s.SyncWithServer(other.srv.URL, "", time.Second); err != nil || !fallback {
		t.Fatalf("after adoption other servers are ignored: fallback=%v err=%v", fallback, err)
	}
}

// Older bapedge builds (and other components) rewrite policy-state.json with a struct that has no
// signature fields. That must neither break verification nor be able to change signed rules.
func TestLegacyStateRewriteByOlderBuildDoesNotBreakOrChangeSignedRules(t *testing.T) {
	cp := newFakeCP(t)
	cp.readEx = false
	s := newManagedStore(t, cp, "asset-A")

	// Exactly what an old build writes after a "successful sync": no signature, flags loosened.
	old := `{"version": 9, "digest": "deadbeef", "kill_switch": false, "strict_tool_enforcement": false, "enforcement_tier": "tier_1_standard", "last_sync": "2026-11-13T21:05:00Z"}`
	if err := os.WriteFile(filepath.Join(s.Directory(), "policy-state.json"), []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, st, err := s.Current()
	if err != nil {
		t.Fatalf("signed rules must still verify after an older build rewrote the legacy file: %v", err)
	}
	if st.ZSPReadExempt || st.Version != 1 || st.Digest == "deadbeef" {
		t.Fatalf("the legacy rewrite must not change signed rules: %+v", st)
	}
}

func TestEditingLegacyStateCannotLoosenSignedRules(t *testing.T) {
	cp := newFakeCP(t)
	cp.readEx = false
	s := newManagedStore(t, cp, "asset-A")
	st, _ := s.LoadState()
	st.ZSPReadExempt = true
	st.SigAlg, st.SignatureEd25519 = "", ""
	data, _ := json.Marshal(st)
	_ = os.WriteFile(filepath.Join(s.Directory(), "policy-state.json"), data, 0600)
	if _, _, got, err := s.Current(); err != nil || got.ZSPReadExempt {
		t.Fatalf("legacy edits must have no effect on signed rules: %+v err=%v", got, err)
	}
}

// Enrolling against some other control plane (a throwaway test instance) must not silently
// replace the pin of a machine that is enrolled with a real one.
func TestEnrollmentAgainstADifferentControlPlaneDoesNotReplaceThePin(t *testing.T) {
	real := newFakeCP(t)
	s := newManagedStore(t, real, "asset-A")
	if pin, _ := s.LoadPin(); pin.ServerURL == "" {
		t.Fatal("setup: first contact must have recorded the control plane URL")
	}
	other := newFakeCP(t)
	if err := s.PinEnrollment(other.keyID, pubB64(other), "asset-A", other.srv.URL); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("enrolling elsewhere must be refused, got %v", err)
	}
	if pin, _ := s.LoadPin(); pin.KeyID != real.keyID {
		t.Fatal("pin must be unchanged")
	}
	t.Setenv("BAP_ALLOW_REPIN", "1")
	if err := s.PinEnrollment(other.keyID, pubB64(other), "asset-A", other.srv.URL); err != nil {
		t.Fatalf("a deliberate move must be possible: %v", err)
	}
}

func TestReEnrollingWithTheSameControlPlaneAfterKeyLossIsAllowed(t *testing.T) {
	real := newFakeCP(t)
	s := newManagedStore(t, real, "asset-A")
	fresh := newFakeCP(t)
	if err := s.PinEnrollment(fresh.keyID, pubB64(fresh), "asset-A", real.srv.URL); err != nil {
		t.Fatalf("same control plane, new key (key loss) must re-enroll without extra steps: %v", err)
	}
}

// If the first bundle a machine pins for cannot be accepted, the pin is undone: a machine must not be
// left managed (and failing closed) with an old unsigned cache and no signed rules.
func TestFirstContactPinIsUndoneWhenTheFirstBundleIsRejected(t *testing.T) {
	cp := newFakeCP(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/policy/pubkey") {
			_ = json.NewEncoder(w).Encode(map[string]string{"alg": "ed25519", "key_id": cp.keyID, "public_key": pubB64(cp)})
			return
		}
		b := cp.bundleFor("") // properly signed...
		b.Digest = strings.Repeat("0", 64) // ...but its digest does not match its content
		_ = json.NewEncoder(w).Encode(map[string]any{"directive": "UPDATE_REQUIRED", "bundle": b})
	}))
	t.Cleanup(bad.Close)

	s := New(t.TempDir())
	if _, _, err := s.SyncWithServer(bad.URL, "", 2*time.Second); err == nil {
		t.Fatal("a bundle with a wrong digest must be rejected")
	}
	if s.Managed() {
		t.Fatal("a rejected first bundle must not leave the machine pinned (managed) without signed rules")
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
