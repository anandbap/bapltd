package policy

import "testing"

func TestSyncProofGolden(t *testing.T) {
	if got := string(SyncProofPayload("nonce", "UPDATE_REQUIRED", "sig")); got != `["bap-policy-sync-v1","nonce","UPDATE_REQUIRED","sig"]` {
		t.Fatal(got)
	}
}

// Legacy clients send no nonce and must get exactly the old response; a CURRENT answer carries
// no bundle, so there is nothing to prove.
func TestSyncProofOnlyForNonceBoundBundleResponses(t *testing.T) {
	s := NewStore("permit(principal, action, resource);", "")
	s.SetSigner(newTestSigner(t))
	if resp := s.Sync(SyncRequest{AssetID: "asset", InstalledVersion: 0}); resp.Bundle == nil || resp.SyncSignature != "" {
		t.Fatalf("a request without a nonce must not receive a proof: %+v", resp)
	}
	first := s.Sync(SyncRequest{AssetID: "asset", SyncNonce: "n1"})
	if first.Bundle == nil || first.SyncSignature == "" {
		t.Fatalf("expected a bundle with a proof: %+v", first)
	}
	// The proof is request-bound: the same nonce and bundle give a stable proof, a new nonce does not.
	if again := s.Sync(SyncRequest{AssetID: "asset", SyncNonce: "n2"}); again.SyncSignature == first.SyncSignature {
		t.Fatal("different nonces produced the same proof")
	}
	current := s.Sync(SyncRequest{
		AssetID: "asset", SyncNonce: "n3", InstalledVersion: first.Bundle.Version, InstalledDigest: first.Bundle.Digest,
		InstalledKeyID: s.signer.KeyID(), InstalledAssetID: "asset",
	})
	if current.Directive != DirectiveCurrent || current.Bundle != nil || current.SyncSignature != "" {
		t.Fatalf("CURRENT must carry no bundle and no proof: %+v", current)
	}
}

func TestSyncSignsFreshAuthorityEvenForLowerVersion(t *testing.T) {
	s := NewStore("permit(principal, action, resource);", "")
	signer := newTestSigner(t)
	s.SetSigner(signer)
	req := SyncRequest{AssetID: "asset", InstalledVersion: 1700000000, SyncNonce: "fresh-challenge"}
	for _, kill := range []bool{false, true} {
		s.SetKillSwitch(kill)
		resp := s.Sync(req)
		if resp.Bundle == nil || resp.Bundle.Version >= req.InstalledVersion {
			t.Fatal("expected lower server version")
		}
		payload := SyncProofPayload(req.SyncNonce, string(resp.Directive), resp.Bundle.SignatureEd25519)
		if !VerifyEd25519(signer.PublicKeyB64(), payload, resp.SyncSignature) {
			t.Fatal("missing or invalid live authority proof")
		}
		if VerifyEd25519(signer.PublicKeyB64(), SyncProofPayload("other-request", string(resp.Directive), resp.Bundle.SignatureEd25519), resp.SyncSignature) {
			t.Fatal("proof was not bound to request")
		}
	}
}
