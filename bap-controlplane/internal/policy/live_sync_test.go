package policy

import "testing"

func TestSyncProofGolden(t *testing.T) {
	if got := string(SyncProofPayload("nonce", "UPDATE_REQUIRED", "sig")); got != `["bap-policy-sync-v1","nonce","UPDATE_REQUIRED","sig"]` {
		t.Fatal(got)
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
