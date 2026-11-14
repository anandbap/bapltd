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
