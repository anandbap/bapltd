package policystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

const testCedar = "permit(principal, action, resource);"

type fakeCP struct {
	t       *testing.T
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	keyID   string
	version uint64
	readEx  bool
	kill    bool
	srv     *httptest.Server

	// Authenticated-enrollment behaviour: when enrolledAsset is set, a request carrying
	// "Bearer <token>" is issued a bundle for enrolledAsset (the body is ignored); anyone else
	// gets the fleet bundle signed for no asset.
	token         string
	enrolledAsset string
	chain         []rotationLink
	lastAuth      string
}

func keyIDOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// rotate switches the control plane to a new key and records a link signed by the old one.
func (cp *fakeCP) rotate() {
	oldPriv, oldID := cp.priv, cp.keyID
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	newPub := base64.StdEncoding.EncodeToString(pub)
	newID := keyIDOf(pub)
	payload := []byte("bap-policy-rotation-v1\nold=" + oldID + "\nnew=" + newID + "\nnew_pub=" + newPub + "\n")
	cp.chain = append(cp.chain, rotationLink{OldKeyID: oldID, NewKeyID: newID, NewPublic: newPub, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(oldPriv, payload))})
	cp.pub, cp.priv, cp.keyID = pub, priv, newID
	cp.version++
}

func newFakeCP(t *testing.T) *fakeCP {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(pub)
	cp := &fakeCP{t: t, pub: pub, priv: priv, keyID: hex.EncodeToString(sum[:8]), version: 1, readEx: true, token: "ws-token-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy/pubkey", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"alg": "ed25519", "key_id": cp.keyID, "public_key": base64.StdEncoding.EncodeToString(cp.pub)})
	})
	mux.HandleFunc("/api/v1/policy/sync", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AssetID          string `json:"asset_id"`
			InstalledVersion uint64 `json:"installed_version"`
			InstalledKeyID   string `json:"installed_key_id"`
			InstalledAsset   string `json:"installed_asset_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		cp.lastAuth = r.Header.Get("Authorization")
		asset := req.AssetID
		if cp.enrolledAsset != "" {
			asset = ""
			if cp.lastAuth == "Bearer "+cp.token {
				asset = cp.enrolledAsset
			}
			req.AssetID = asset
		}
		b := cp.bundleFor(asset)
		directive := "UPDATE_REQUIRED"
		if cp.kill {
			directive = "KILL_SWITCH"
		} else if req.InstalledVersion == b.Version && req.InstalledKeyID == cp.keyID && req.InstalledAsset == req.AssetID {
			_ = json.NewEncoder(w).Encode(map[string]any{"directive": "CURRENT"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"directive": directive, "bundle": b})
	})
	cp.srv = httptest.NewServer(mux)
	t.Cleanup(cp.srv.Close)
	return cp
}

func (cp *fakeCP) bundleFor(asset string) Bundle {
	b := Bundle{
		Version: cp.version, PolicyCedar: testCedar, KillSwitch: cp.kill,
		EnforcementTier: "tier_1_standard", ZSPReadExempt: cp.readEx,
		UpdatedAt: "2026-11-13T00:00:00Z", AssetID: asset, SigAlg: "ed25519", KeyID: cp.keyID,
	}
	b.Digest = ComputeDigest(b.PolicyCedar, "")
	payload := canonicalPayload(asset, b.Version, b.Digest, b.KillSwitch, b.StrictToolEnforcement, b.EnforcementTier, b.ZSPReadExempt, b.UpdatedAt)
	b.SignatureEd25519 = base64.StdEncoding.EncodeToString(ed25519.Sign(cp.priv, payload))
	b.KeyChain = cp.chain
	return b
}

func newManagedStore(t *testing.T, cp *fakeCP, asset string) *Store {
	t.Helper()
	s := New(t.TempDir())
	s.SetAssetID(asset)
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); err != nil {
		t.Fatalf("initial signed sync failed: %v", err)
	}
	if !s.Managed() {
		t.Fatal("first signed sync must pin the control plane key")
	}
	return s
}

// Golden vector shared with bap-controlplane/internal/policy: the two canonical strings must
// never drift, or every client would reject every bundle.
func TestCanonicalPayloadGolden(t *testing.T) {
	got := string(canonicalPayload("asset-1", 7, "abc", true, false, "tier_1_standard", true, "2026-01-02T03:04:05Z"))
	want := "bap-policy-v2\nasset=asset-1\nversion=7\ndigest=abc\nkill=true\nstrict=false\ntier=tier_1_standard\nzsp_read_exempt=true\nupdated_at=2026-01-02T03:04:05Z\n"
	if got != want {
		t.Fatalf("canonical payload drifted from the control plane format:\n%q\n%q", got, want)
	}
}

func TestFirstSyncPinsKeyAndStoresSignedState(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	_, _, st, err := s.Current()
	if err != nil {
		t.Fatalf("signed state must verify: %v", err)
	}
	if !st.ZSPReadExempt || st.AssetID != "asset-A" || st.KeyID != cp.keyID {
		t.Fatalf("unexpected state: %+v", st)
	}
}

func TestEditingAnyEnforcementFlagLocallyIsDetected(t *testing.T) {
	for name, mutate := range map[string]func(*PolicyState){
		"zsp_read_exempt": func(p *PolicyState) { p.ZSPReadExempt = !p.ZSPReadExempt },
		"strict":          func(p *PolicyState) { p.StrictToolEnforcement = !p.StrictToolEnforcement },
		"tier":            func(p *PolicyState) { p.EnforcementTier = "tier_2_strict" },
		"kill_switch":     func(p *PolicyState) { p.KillSwitch = !p.KillSwitch },
		"version":         func(p *PolicyState) { p.Version += 5 },
	} {
		cp := newFakeCP(t)
		s := newManagedStore(t, cp, "asset-A")
		st, _ := s.LoadState()
		mutate(&st)
		data, _ := json.Marshal(st)
		if err := os.WriteFile(filepath.Join(s.Directory(), "policy-state.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := s.Current(); !errors.Is(err, ErrPolicyTampered) {
			t.Errorf("editing %s must be reported as tampering, got %v", name, err)
		}
	}
}

func TestDeletingStateDoesNotDowngradeToLocalPolicy(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	_ = os.Remove(filepath.Join(s.Directory(), "policy-state.json"))
	// A permissive policy.cedar sitting in the working directory must not be adopted.
	wd := t.TempDir()
	_ = os.WriteFile(filepath.Join(wd, "policy.cedar"), []byte(testCedar), 0600)
	old, _ := os.Getwd()
	_ = os.Chdir(wd)
	defer os.Chdir(old)
	if _, _, _, err := s.Current(); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("missing state on an enrolled machine must fail closed, got %v", err)
	}
}

func TestEditingCachedCedarIsDetected(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	_ = os.WriteFile(filepath.Join(s.Directory(), "policy.cedar"), []byte(testCedar+"\n// weakened"), 0600)
	if _, _, _, err := s.Current(); err == nil {
		t.Fatal("modified policy.cedar must be rejected")
	}
}

func TestBundleForAnotherAssetIsRejected(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	if err := s.Accept(cp.bundleFor("asset-B")); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("replayed bundle for another machine must be rejected, got %v", err)
	}
}

func TestBundleSignedByUnpinnedKeyIsRejected(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	rogue := newFakeCP(t)
	rogue.version = 99
	if err := s.Accept(rogue.bundleFor("asset-A")); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("bundle from an unpinned key must be rejected, got %v", err)
	}
}

func TestDifferentKeyOfferedLaterIsRefusedNotRepinned(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	rogue := newFakeCP(t)
	if err := s.PinKey(rogue.keyID, base64.StdEncoding.EncodeToString(rogue.pub), ""); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("re-pinning a different key must be refused, got %v", err)
	}
}

func TestControlPlaneDownKeepsLastSignedRules(t *testing.T) {
	cp := newFakeCP(t)
	cp.readEx = false
	s := newManagedStore(t, cp, "asset-A")
	cp.srv.Close()
	b, fallback, err := s.SyncWithServer(cp.srv.URL, "", 300*time.Millisecond)
	if err != nil || !fallback {
		t.Fatalf("offline sync must fall back to cached signed rules: fallback=%v err=%v", fallback, err)
	}
	_, _, st, _ := s.Current()
	if st.ZSPReadExempt || b.Version != 1 {
		t.Fatalf("last signed rules must stay in force offline: %+v", st)
	}
}

func TestControlPlaneDownPlusTamperFailsClosed(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	st, _ := s.LoadState()
	st.ZSPReadExempt = !st.ZSPReadExempt
	data, _ := json.Marshal(st)
	_ = os.WriteFile(filepath.Join(s.Directory(), "policy-state.json"), data, 0600)
	cp.srv.Close()
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("tampered rules with the control plane down must fail closed, got %v", err)
	}
}

func TestChangeOnControlPlaneFlowsOnNextSyncAndIsAccepted(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	cp.version, cp.readEx = 2, false
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	_, _, st, err := s.Current()
	if err != nil || st.Version != 2 || st.ZSPReadExempt {
		t.Fatalf("admin change must be picked up: %+v err=%v", st, err)
	}
}

func TestSignedKillSwitchIsPersistedForOffline(t *testing.T) {
	cp := newFakeCP(t)
	s := newManagedStore(t, cp, "asset-A")
	cp.version, cp.kill = 2, true
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2*time.Second); !errors.Is(err, ErrKillSwitchActive) {
		t.Fatalf("expected kill switch, got %v", err)
	}
	cp.srv.Close()
	if _, _, _, err := s.Current(); !errors.Is(err, ErrKillSwitchActive) {
		t.Fatalf("signed kill switch must persist while the control plane is down, got %v", err)
	}
}

func TestAssetIDIsStableAndNotEnvironmentDerived(t *testing.T) {
	t.Setenv("BAP_ASSET_ID", "")
	t.Setenv("USERNAME", "alice")
	t.Setenv("USER", "alice")
	a := ResolveAssetID()
	t.Setenv("USERNAME", "mallory")
	t.Setenv("USER", "mallory")
	if b := ResolveAssetID(); a != b || !strings.HasPrefix(a, "asset-") {
		t.Fatalf("asset id must not change with the user name: %q vs %q", a, b)
	}
}
