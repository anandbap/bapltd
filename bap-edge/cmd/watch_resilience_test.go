package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCleanupStaleSessionMarkers(t *testing.T) {
	// Setup test isolated directory
	sessionsDir := filepath.Join(".bap", "sessions")
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		t.Fatalf("failed to create test sessions dir: %v", err)
	}
	defer os.RemoveAll(".bap")

	// 1. Create a marker for a dead PID (99999999 is definitely dead)
	deadPID := 99999999
	deadPath := filepath.Join(sessionsDir, "pid-99999999.json")
	deadMarker := map[string]any{
		"pid":        deadPID,
		"session_id": "sess-dead-test",
		"started_at": time.Now().Add(-1 * time.Hour),
	}
	deadBytes, _ := json.Marshal(deadMarker)
	_ = os.WriteFile(deadPath, deadBytes, 0600)

	// Also write the hash-named session marker
	deadHashMarker := sessionMarkerPath("sess-dead-test")
	_ = os.WriteFile(deadHashMarker, deadBytes, 0600)

	// 2. Create a marker for the current process PID (alive)
	alivePID := os.Getpid()
	alivePath := filepath.Join(sessionsDir, "pid-alive-test.json")
	aliveMarker := map[string]any{
		"pid":        alivePID,
		"session_id": "sess-alive-test",
		"started_at": time.Now(),
	}
	aliveBytes, _ := json.Marshal(aliveMarker)
	_ = os.WriteFile(alivePath, aliveBytes, 0600)

	// Run cleanup
	cleanupStaleSessionMarkers()

	// Verify dead PID markers were purged
	if _, err := os.Stat(deadPath); !os.IsNotExist(err) {
		t.Errorf("expected dead PID marker to be removed, but still exists: %s", deadPath)
	}
	if _, err := os.Stat(deadHashMarker); !os.IsNotExist(err) {
		t.Errorf("expected dead hash marker to be removed, but still exists: %s", deadHashMarker)
	}

	// Verify alive PID marker was preserved
	if _, err := os.Stat(alivePath); os.IsNotExist(err) {
		t.Errorf("expected alive PID marker to be preserved, but was deleted")
	}
}

func TestPostJSONWithRetrySuccessAfterTransientFailure(t *testing.T) {
	var attempts atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := attempts.Add(1)
		if val == 1 {
			// First attempt fails transiently with 503 Service Unavailable
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		// Second attempt succeeds
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer ts.Close()

	payload := map[string]string{"test": "retry_payload"}
	err := postJSONWithRetry(ts.URL, payload, 3, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("expected retry to succeed on 2nd attempt, got error: %v", err)
	}
	if attempts.Load() != 2 {
		t.Errorf("expected exactly 2 attempts, got %d", attempts.Load())
	}
}

func TestPostJSONWithRetryExhaustion(t *testing.T) {
	var attempts atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "persistent internal error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	payload := map[string]string{"test": "fail_payload"}
	err := postJSONWithRetry(ts.URL, payload, 3, 20*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error after exhausting retries, got nil")
	}
	if attempts.Load() != 3 {
		t.Errorf("expected exactly 3 attempts before failure, got %d", attempts.Load())
	}
}
