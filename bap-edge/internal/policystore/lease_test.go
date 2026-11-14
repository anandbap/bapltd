package policystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestSignedLeaseCannotBeExtendedLocally(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	store := New(t.TempDir())
	if err := store.PinEnrollment("key-test", base64.StdEncoding.EncodeToString(pub), "asset-test", ""); err != nil {
		t.Fatal(err)
	}
	b := Bundle{Version: 1, PolicyCedar: "permit(principal, action, resource);", AssetID: "asset-test", SigAlg: "ed25519", KeyID: "key-test", ValidUntil: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}
	b.Digest = ComputeDigest(b.PolicyCedar, "")
	payload := canonicalPayload(b.AssetID, b.Version, b.Digest, false, false, "", false, "", nil...)
	payload = append(payload, []byte("valid_until="+b.ValidUntil+"\n")...)
	b.SignatureEd25519 = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	if err := store.Accept(b); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Current(); !errors.Is(err, ErrPolicyExpired) {
		t.Fatalf("expired authority accepted: %v", err)
	}
	b.ValidUntil = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := store.Accept(b); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("unsigned lease extension accepted: %v", err)
	}
}
