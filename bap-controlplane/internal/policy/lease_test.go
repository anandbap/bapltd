package policy

import (
	"strings"
	"testing"
	"time"
)

func TestSignedLeaseRefreshesUnchangedPolicy(t *testing.T) {
	store := NewStore("permit(principal, action, resource);", "")
	signer, err := LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetSigner(signer)
	if err := store.SetMaxPolicyAge(time.Hour); err != nil {
		t.Fatal(err)
	}
	first := store.Sync(SyncRequest{AssetID: "asset", SupportsPolicyLease: true})
	if first.Bundle == nil || first.Bundle.ValidUntil == "" {
		t.Fatal("missing signed lease")
	}
	if !VerifyEd25519(signer.PublicKeyB64(), CanonicalBundlePayload(*first.Bundle, "asset"), first.Bundle.SignatureEd25519) {
		t.Fatal("lease signature invalid")
	}
	second := store.Sync(SyncRequest{AssetID: "asset", InstalledVersion: first.Bundle.Version, InstalledDigest: first.Bundle.Digest, InstalledKeyID: signer.KeyID(), InstalledAssetID: "asset", SupportsPolicyLease: true})
	if second.Directive == DirectiveCurrent || second.Bundle == nil {
		t.Fatal("unchanged policy did not renew its lease")
	}
	if !strings.Contains(string(CanonicalBundlePayload(*second.Bundle, "asset")), "valid_until=") {
		t.Fatal("expiry not signed")
	}
}
