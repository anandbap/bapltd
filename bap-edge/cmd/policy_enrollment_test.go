package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"bap-edge/internal/policystore"
)

// An enrollment whose first signed-policy sync fails (control plane unreachable, rejected bundle)
// must leave the machine exactly as it was. Leaving the pin behind without signed rules made every
// later bapedge command fail closed - the CI failure this guards against.
func TestFailedEnrollmentSyncLeavesNoPin(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(pub)
	keyID := hex.EncodeToString(sum[:8])

	store := policystore.New(policystore.DefaultPolicyDir())
	store.RemovePin()
	if store.Managed() {
		t.Fatal("test setup: expected an unmanaged store")
	}

	// 127.0.0.1:1 refuses connections immediately: the first sync cannot succeed.
	pinPolicyEnrollment(keyID, base64.StdEncoding.EncodeToString(pub), "asset-test", "http://127.0.0.1:1", "token")

	if store.Managed() {
		store.RemovePin()
		t.Fatal("a failed first policy sync must undo the pin, not leave the machine pinned without signed rules")
	}
}

func TestFailedReEnrollmentRestoresThePreviousPin(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	idOf := func(p ed25519.PublicKey) string { s := sha256.Sum256(p); return hex.EncodeToString(s[:8]) }

	store := policystore.New(policystore.DefaultPolicyDir())
	store.RemovePin()
	t.Cleanup(store.RemovePin)
	if err := store.PinEnrollment(idOf(pubA), base64.StdEncoding.EncodeToString(pubA), "asset-test", ""); err != nil {
		t.Fatal(err)
	}

	pinPolicyEnrollment(idOf(pubB), base64.StdEncoding.EncodeToString(pubB), "asset-test", "http://127.0.0.1:1", "token")

	got, ok := store.LoadPin()
	if !ok || got.KeyID != idOf(pubA) {
		t.Fatalf("a failed re-enrollment must restore the previous pin, got %+v", got)
	}
}
