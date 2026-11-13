package policy

import (
	"strings"
	"testing"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	sg, err := LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return sg
}

// Golden vector shared with bap-edge/internal/policystore (TestCanonicalPayloadGolden): the
// two sides must produce the identical signed string or every client rejects every bundle.
func TestCanonicalPayloadGolden(t *testing.T) {
	b := Bundle{Version: 7, Digest: "abc", KillSwitch: true, StrictToolEnforcement: false,
		EnforcementTier: "tier_1_standard", ZSPReadExempt: true, UpdatedAt: "2026-01-02T03:04:05Z"}
	got := string(CanonicalBundlePayload(b, "asset-1"))
	want := "bap-policy-v2\nasset=asset-1\nversion=7\ndigest=abc\nkill=true\nstrict=false\ntier=tier_1_standard\nzsp_read_exempt=true\nupdated_at=2026-01-02T03:04:05Z\n"
	if got != want {
		t.Fatalf("canonical payload changed:\n%q\n%q", got, want)
	}
}

func TestSignerPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKeyB64() != b.PublicKeyB64() || a.KeyID() != b.KeyID() {
		t.Fatal("signing key must survive a control plane restart")
	}
}

func TestSyncResponseIsAssetScopedAndVerifiable(t *testing.T) {
	st := NewStore("permit(principal, action, resource);", "{}")
	sg := newTestSigner(t)
	st.SetSigner(sg)

	resp := st.Sync(SyncRequest{AssetID: "wkstn-A"})
	if resp.Directive != DirectiveUpdateRequired || resp.Bundle == nil {
		t.Fatalf("expected a signed bundle, got %+v", resp)
	}
	b := *resp.Bundle
	if b.AssetID != "wkstn-A" || b.SigAlg != SigAlgEd25519 || b.KeyID != sg.KeyID() {
		t.Fatalf("bundle not stamped for asset: %+v", b)
	}
	if !VerifyEd25519(sg.PublicKeyB64(), CanonicalBundlePayload(b, "wkstn-A"), b.SignatureEd25519) {
		t.Fatal("signature must verify for the asset it was issued to")
	}
	// Replay to another asset must fail.
	if VerifyEd25519(sg.PublicKeyB64(), CanonicalBundlePayload(b, "wkstn-B"), b.SignatureEd25519) {
		t.Fatal("bundle signed for wkstn-A must not verify for wkstn-B")
	}
}

func TestEveryEnforcementFlagIsCovered(t *testing.T) {
	st := NewStore("permit(principal, action, resource);", "{}")
	sg := newTestSigner(t)
	st.SetSigner(sg)
	b := *st.Sync(SyncRequest{AssetID: "w"}).Bundle

	mutations := map[string]func(*Bundle){
		"kill_switch":     func(x *Bundle) { x.KillSwitch = !x.KillSwitch },
		"strict":          func(x *Bundle) { x.StrictToolEnforcement = !x.StrictToolEnforcement },
		"tier":            func(x *Bundle) { x.EnforcementTier = "tier_2_strict" },
		"zsp_read_exempt": func(x *Bundle) { x.ZSPReadExempt = !x.ZSPReadExempt },
		"version":         func(x *Bundle) { x.Version++ },
		"digest":          func(x *Bundle) { x.Digest = strings.Repeat("0", 64) },
	}
	for name, mutate := range mutations {
		tampered := b
		mutate(&tampered)
		if VerifyEd25519(sg.PublicKeyB64(), CanonicalBundlePayload(tampered, "w"), b.SignatureEd25519) {
			t.Errorf("editing %s must invalidate the signature", name)
		}
	}
}

func TestCurrentRequiresSignedCopyForOwnAsset(t *testing.T) {
	st := NewStore("permit(principal, action, resource);", "{}")
	sg := newTestSigner(t)
	st.SetSigner(sg)
	b := *st.Sync(SyncRequest{AssetID: "w1"}).Bundle

	same := st.Sync(SyncRequest{AssetID: "w1", InstalledVersion: b.Version, InstalledDigest: b.Digest, InstalledKeyID: sg.KeyID(), InstalledAssetID: "w1"})
	if same.Directive != DirectiveCurrent {
		t.Fatalf("expected CURRENT, got %s", same.Directive)
	}
	other := st.Sync(SyncRequest{AssetID: "w2", InstalledVersion: b.Version, InstalledDigest: b.Digest, InstalledKeyID: sg.KeyID(), InstalledAssetID: "w1"})
	if other.Directive != DirectiveUpdateRequired {
		t.Fatal("a copy signed for another asset must not count as current")
	}
	legacy := st.Sync(SyncRequest{AssetID: "w1", InstalledVersion: b.Version, InstalledDigest: b.Digest})
	if legacy.Directive != DirectiveUpdateRequired {
		t.Fatal("an unsigned installed copy must be replaced by a signed one")
	}
}

func TestKillSwitchBundleIsSignedToo(t *testing.T) {
	st := NewStore("permit(principal, action, resource);", "{}")
	sg := newTestSigner(t)
	st.SetSigner(sg)
	st.SetKillSwitch(true)
	resp := st.Sync(SyncRequest{AssetID: "w"})
	if resp.Directive != DirectiveKillSwitch || resp.Bundle == nil || resp.Bundle.SignatureEd25519 == "" {
		t.Fatalf("kill switch must be delivered as a signed bundle: %+v", resp)
	}
}

func TestReadExemptDefaultsOnAndSurvivesPolicyUpdates(t *testing.T) {
	st := NewStore("permit(principal, action, resource);", "{}")
	if !st.GetBundle().ZSPReadExempt {
		t.Fatal("developer-friendly default: read-only inspection is exempt")
	}
	st.Update("permit(principal, action, resource);", "{}", false)
	if !st.GetBundle().ZSPReadExempt {
		t.Fatal("policy updates must not reset enforcement settings")
	}
}
