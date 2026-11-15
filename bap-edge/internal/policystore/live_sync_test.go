package policystore

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestSyncProofGolden(t *testing.T) {
	if got := string(syncProofPayload("nonce", "UPDATE_REQUIRED", "sig")); got != `["bap-policy-sync-v1","nonce","UPDATE_REQUIRED","sig"]` {
		t.Fatal(got)
	}
}

// A live proof must come from the pinned key and be bound to the directive actually delivered.
// A proof from another key, or one issued for a different directive (for example an ordinary
// UPDATE_REQUIRED proof attached to a swapped KILL_SWITCH), must not authorize a downgrade.
func TestLiveProofFromWrongKeyOrDirectiveIsRejected(t *testing.T) {
	cp := newFakeCP(t)
	cp.version = 1700000000
	s := newManagedStore(t, cp, "asset-forged")
	cp.version = 2
	cp.liveProof = true

	_, otherPriv, _ := ed25519.GenerateKey(nil)
	cp.proofKey = otherPriv
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", time.Second); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("proof signed by an unpinned key was accepted: %v", err)
	}
	cp.proofKey = nil

	cp.proofDirective = "CURRENT"
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", time.Second); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("proof bound to a different directive was accepted: %v", err)
	}
	cp.proofDirective = ""

	if _, _, st, err := s.Current(); err != nil || st.Version != 1700000000 {
		t.Fatalf("rejected proofs must leave the cached policy untouched: %+v %v", st, err)
	}
	if b, _, err := s.SyncWithServer(cp.srv.URL, "", time.Second); err != nil || b.Version != 2 {
		t.Fatalf("a correct proof must still be accepted afterwards: %+v %v", b, err)
	}
}

func TestLiveServerCanLowerVersionButLocalReplayCannot(t *testing.T) {
	cp := newFakeCP(t)
	cp.version = 1700000000
	s := newManagedStore(t, cp, "asset-live")
	cp.version = 2
	old := cp.bundleFor("asset-live")
	if err := s.Accept(old); !errors.Is(err, ErrRollbackRejected) {
		t.Fatalf("local signed downgrade accepted: %v", err)
	}
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", time.Second); !errors.Is(err, ErrRollbackRejected) {
		t.Fatalf("legacy server without freshness proof bypassed rollback guard: %v", err)
	}
	cp.liveProof = true
	if b, offline, err := s.SyncWithServer(cp.srv.URL, "", time.Second); err != nil || offline || b.Version != 2 {
		t.Fatalf("fresh server downgrade failed: bundle=%+v offline=%v err=%v", b, offline, err)
	}
	// New processes must read the lower version as verified authority without changing the pin.
	reopened := New(s.Directory())
	if _, _, st, err := reopened.Current(); err != nil || st.Version != 2 {
		t.Fatalf("lower signed policy not durable: state=%+v err=%v", st, err)
	}
	cp.version = 3
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", time.Second); err != nil {
		t.Fatal(err)
	}
	cp.version = 1
	b := cp.bundleFor("asset-live")
	cp.replayProof = base64.StdEncoding.EncodeToString(ed25519.Sign(cp.priv, syncProofPayload("previous-request-nonce", "UPDATE_REQUIRED", b.SignatureEd25519)))
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", time.Second); !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("replayed live proof accepted: %v", err)
	}
	if _, _, st, err := s.Current(); err != nil || st.Version != 3 {
		t.Fatalf("replay altered cached policy: %+v %v", st, err)
	}
	cp.replayProof = ""
	cp.kill = true
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", time.Second); !errors.Is(err, ErrKillSwitchActive) {
		t.Fatalf("lower-version live kill switch failed: %v", err)
	}
	if _, _, _, err := reopened.Current(); !errors.Is(err, ErrKillSwitchActive) {
		t.Fatalf("kill switch not persisted: %v", err)
	}
	cp.kill = false
	cp.version = 0
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", time.Second); err != nil {
		t.Fatalf("live recovery from kill switch failed: %v", err)
	}
}
