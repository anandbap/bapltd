package policystore

import (
	"bap-edge/internal/httptransport"
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
