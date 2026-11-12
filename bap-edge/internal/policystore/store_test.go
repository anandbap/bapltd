package policystore

import (
	"bap-edge/internal/httptransport"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPolicyStore_AcceptAndCurrent(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policystore-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	store := New(tempDir)

	cedar := `permit(principal, action, resource);`
	schema := `{}`
	digest := ComputeDigest(cedar, schema)

	bundle := Bundle{
		Version:     1,
		Digest:      digest,
		PolicyCedar: cedar,
		SchemaJSON:  schema,
	}

	if err := store.Accept(bundle); err != nil {
		t.Fatalf("failed to accept bundle: %v", err)
	}

	cedarPath, schemaPath, state, err := store.Current()
	if err != nil {
		t.Fatalf("expected current policy, got error: %v", err)
	}

	if state.Version != 1 {
		t.Errorf("expected version 1, got %d", state.Version)
	}
	if filepath.Base(cedarPath) != "policy.cedar" {
		t.Errorf("unexpected cedar path: %s", cedarPath)
	}
	if schemaPath == "" {
		t.Errorf("expected schema path to be resolved")
	}

	// Tamper detection: invalid digest
	badBundle := Bundle{
		Version:     2,
		Digest:      "corrupted-digest",
		PolicyCedar: cedar,
	}
	if err := store.Accept(badBundle); err == nil {
		t.Fatalf("expected digest mismatch error, got nil")
	}

	// Rollback protection: older version
	olderBundle := Bundle{
		Version:     0,
		Digest:      digest,
		PolicyCedar: cedar,
	}
	if err := store.Accept(olderBundle); err == nil {
		t.Fatalf("expected rollback error, got nil")
	}

	// On-disk tamper detection: modify policy.cedar directly on disk
	tamperedCedar := `permit(principal, action, resource); // tampered line`
	if err := os.WriteFile(cedarPath, []byte(tamperedCedar), 0600); err != nil {
		t.Fatalf("failed to write tampered cedar: %v", err)
	}
	if _, _, _, err := store.Current(); err == nil {
		t.Fatalf("expected ErrDigestMismatch when policy.cedar is tampered on disk, got nil")
	}
}

func TestPolicyStore_OfflineFallback(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "offline-test-*")
	defer os.RemoveAll(tempDir)

	store := New(tempDir)
	cedar := `permit(principal, action, resource);`
	digest := ComputeDigest(cedar, "")

	_ = store.Accept(Bundle{
		Version:     1,
		Digest:      digest,
		PolicyCedar: cedar,
	})

	// Server is dead / unreachable port
	deadServerURL := "http://127.0.0.1:59999"
	bundle, isFallback, err := store.SyncWithServer(deadServerURL, "agent-1", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("expected seamless offline fallback, got err: %v", err)
	}

	if !isFallback {
		t.Errorf("expected isFallback to be true when server is unreachable")
	}

	if bundle.Version != 1 {
		t.Errorf("expected cached version 1, got %d", bundle.Version)
	}
	if bundle.PolicyCedar != cedar {
		t.Errorf("expected cached cedar content to match")
	}
}

func TestPolicyStore_PersistentKillSwitch(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "killswitch-test-*")
	defer os.RemoveAll(tempDir)

	store := New(tempDir)

	mockURL := "https://mock.controlplane.internal"
	httptransport.MockTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rec).Encode(SyncResponse{
			Directive: "KILL_SWITCH",
		})
		return rec.Result(), nil
	})
	defer func() { httptransport.MockTransport = nil }()

	_, _, err := store.SyncWithServer(mockURL, "agent-1", time.Second)
	if err != ErrKillSwitchActive {
		t.Fatalf("expected ErrKillSwitchActive, got %v", err)
	}

	// Even offline, kill switch remains locked
	_, _, _, currentErr := store.Current()
	if currentErr != ErrKillSwitchActive {
		t.Fatalf("expected kill switch to persist offline, got: %v", currentErr)
	}
}

func TestPolicyStore_CryptographicSignatureVerification(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policystore-sig-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	store := New(tempDir)
	key := []byte("corporate-secret-signing-key-32b")
	store.SetSigningKey(key)

	cedar := `permit(principal, action, resource);`
	schema := `{}`
	digest := ComputeDigest(cedar, schema)

	if !VerifyBundleSignature(1, digest, false, "bad-sig", key) {
		// Expected
	} else {
		t.Fatalf("expected bad signature to be rejected")
	}

	validBundle := Bundle{
		Version:     1,
		Digest:      digest,
		PolicyCedar: cedar,
		SchemaJSON:  schema,
	}
	// Sign bundle correctly
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("bap-policy-v1:1:" + digest + ":false"))
	validBundle.Signature = hex.EncodeToString(mac.Sum(nil))

	if err := store.Accept(validBundle); err != nil {
		t.Fatalf("failed to accept signed bundle: %v", err)
	}

	if _, _, _, err := store.Current(); err != nil {
		t.Fatalf("expected valid signed policy, got error: %v", err)
	}

	// Forged signature rejection
	forgedBundle := Bundle{
		Version:     2,
		Digest:      digest,
		Signature:   "forged-signature-attempt",
		PolicyCedar: cedar,
		SchemaJSON:  schema,
	}
	if err := store.Accept(forgedBundle); err == nil {
		t.Fatalf("expected signature verification error on forged bundle, got nil")
	}
}
