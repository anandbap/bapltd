package intent

import (
	"errors"
	"testing"
	"time"
)

func TestIntentManager_AttestAndVerify_Passes(t *testing.T) {
	mgr := NewIntentManager("test-secret-key-12345")
	att, err := mgr.AttestIntent("task-staging-fix", "sess-123", "ciso@corp.internal",
		"Fix staging credential mismatch", []string{"staging", "dev"}, []string{"read", "test", "patch"}, 10*time.Minute)
	if err != nil {
		t.Fatalf("AttestIntent failed: %v", err)
	}

	if att.Signature == "" || att.IntentDigest == "" {
		t.Errorf("expected non-empty digest and signature")
	}

	// Permitted action on staging
	ok, status, err := mgr.VerifyActionAgainstIntent("task-staging-fix", "test", "staging")
	if !ok || err != nil {
		t.Fatalf("expected action to be verified, got ok=%v, status=%s, err=%v", ok, status, err)
	}
	if status != "IntentVerified" {
		t.Errorf("expected IntentVerified, got %s", status)
	}
}

func TestIntentManager_EnvironmentDrift_Blocked(t *testing.T) {
	mgr := NewIntentManager("test-secret-key-12345")
	_, err := mgr.AttestIntent("task-staging-fix", "sess-123", "ciso@corp.internal",
		"Fix staging credential mismatch", []string{"staging"}, []string{"read", "patch"}, 10*time.Minute)
	if err != nil {
		t.Fatalf("AttestIntent failed: %v", err)
	}

	// Action targeting prod while bound to staging -> Blocked
	ok, status, err := mgr.VerifyActionAgainstIntent("task-staging-fix", "patch", "prod")
	if ok || err == nil || !errors.Is(err, ErrIntentDrift) {
		t.Fatalf("expected ErrIntentDrift for prod target, got ok=%v, err=%v", ok, err)
	}
	if status != "EnvironmentDrift" {
		t.Errorf("expected EnvironmentDrift status, got %s", status)
	}
}

func TestIntentManager_DestructiveActionDrift_Blocked(t *testing.T) {
	mgr := NewIntentManager("test-secret-key-12345")
	_, err := mgr.AttestIntent("task-staging-fix", "sess-123", "ciso@corp.internal",
		"Fix staging credential mismatch", []string{"staging"}, []string{"read", "patch"}, 10*time.Minute)
	if err != nil {
		t.Fatalf("AttestIntent failed: %v", err)
	}

	// Attempting delete_volume without destructive authority -> Blocked (Railway incident prevention)
	ok, status, err := mgr.VerifyActionAgainstIntent("task-staging-fix", "delete_volume", "staging")
	if ok || err == nil || !errors.Is(err, ErrIntentDrift) {
		t.Fatalf("expected ErrIntentDrift for delete_volume, got ok=%v, err=%v", ok, err)
	}
	if status != "DestructiveActionDrift" {
		t.Errorf("expected DestructiveActionDrift status, got %s", status)
	}
}
