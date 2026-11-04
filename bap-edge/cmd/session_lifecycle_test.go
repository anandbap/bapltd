package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
)

type mockRoundTripper func(*http.Request) (*http.Response, error)

func (f mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSessionLifecycle_EnsureSessionStartedAndEnded(t *testing.T) {
	os.Setenv("BAP_TEST_ENV", "1")
	defer os.Unsetenv("BAP_TEST_ENV")

	tmpState := t.TempDir()
	os.Setenv("BAP_STATE_DIR", tmpState)
	defer os.Unsetenv("BAP_STATE_DIR")
	state.ResetForTesting()
	defer state.ResetForTesting()

	var mu sync.Mutex
	startedSessions := make(map[string]map[string]any)
	endedSessions := make(map[string]string)

	previousTransport := httptransport.MockTransport
	httptransport.MockTransport = mockRoundTripper(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()

		switch r.URL.Path {
		case "/api/v1/sessions/start":
			bodyBytes, _ := io.ReadAll(r.Body)
			var payload map[string]any
			_ = json.Unmarshal(bodyBytes, &payload)
			sid, _ := payload["session_id"].(string)
			startedSessions[sid] = payload
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"status":"active","session_id":"` + sid + `"}`))),
			}, nil

		case "/api/v1/sessions/end":
			bodyBytes, _ := io.ReadAll(r.Body)
			var payload map[string]any
			_ = json.Unmarshal(bodyBytes, &payload)
			sid, _ := payload["session_id"].(string)
			reason, _ := payload["reason"].(string)
			endedSessions[sid] = reason
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"status":"closed"}`))),
			}, nil

		case "/api/v1/sessions/prompt":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"status":"accepted"}`))),
			}, nil

		default:
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
			}, nil
		}
	})
	t.Cleanup(func() { httptransport.MockTransport = previousTransport })

	clients := []string{"claude-code", "copilot", "antigravity", "opencode", "codex"}

	for _, client := range clients {
		t.Run("Client_"+client, func(t *testing.T) {
			sessionID := "sess-test-" + client + "-" + time.Now().Format("150405.000")

			// 1. Session should not be active initially
			cleanupSessionMarker(sessionID, 0)
			if IsSessionActive(sessionID) {
				t.Fatalf("Session %s should not be active before start", sessionID)
			}

			// 2. EnsureSessionStarted
			err := EnsureSessionStarted(sessionID, client, 9999, "Test initial prompt for "+client)
			if err != nil {
				t.Fatalf("EnsureSessionStarted failed for client %s: %v", client, err)
			}

			// 3. Verify session is marked active locally
			if !IsSessionActive(sessionID) {
				t.Fatalf("Session %s should be marked active locally after EnsureSessionStarted", sessionID)
			}

			// 4. Verify mock Control Plane received start with SPIFFE SVID
			mu.Lock()
			startRecord, exists := startedSessions[sessionID]
			mu.Unlock()
			if !exists {
				t.Fatalf("Control plane did not receive /api/v1/sessions/start for %s", sessionID)
			}

			svid, _ := startRecord["session_svid"].(string)
			if !strings.HasPrefix(svid, "spiffe://bap.internal/workstation/") || !strings.Contains(svid, sessionID) {
				t.Errorf("Unexpected session SVID for %s: %s", client, svid)
			}

			appReceived, _ := startRecord["app_id"].(string)
			if normalizeClientAppID(appReceived) != normalizeClientAppID(client) {
				t.Errorf("App ID mismatch: expected %s, got %s", client, appReceived)
			}

			// 5. Test idempotency: calling EnsureSessionStarted again should succeed cleanly
			err = EnsureSessionStarted(sessionID, client, 9999, "")
			if err != nil {
				t.Fatalf("Subsequent EnsureSessionStarted call should be idempotent, failed: %v", err)
			}

			// 6. EnsureSessionEnded
			err = EnsureSessionEnded(sessionID, "Test clean exit")
			if err != nil {
				t.Fatalf("EnsureSessionEnded failed for %s: %v", client, err)
			}

			// 7. Verify control plane received end
			mu.Lock()
			endReason, endExists := endedSessions[sessionID]
			mu.Unlock()
			if !endExists {
				t.Fatalf("Control plane did not receive /api/v1/sessions/end for %s", sessionID)
			}
			if endReason != "Test clean exit" {
				t.Errorf("Unexpected end reason: %s", endReason)
			}

			// 8. Verify local marker is purged
			markerPath := sessionMarkerPath(sessionID)
			if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
				t.Errorf("Session marker file %s was not cleaned up after end", markerPath)
			}
		})
	}
}

func TestSessionLifecycle_AutoSessionStartOnChatOrToolUse(t *testing.T) {
	// Tests the VS Code scenario: IDE starts, user directly chats or invokes a tool
	// without any preceding SessionStart hook event.
	os.Setenv("BAP_TEST_ENV", "1")
	defer os.Unsetenv("BAP_TEST_ENV")

	tmpState := t.TempDir()
	os.Setenv("BAP_STATE_DIR", tmpState)
	defer os.Unsetenv("BAP_STATE_DIR")
	state.ResetForTesting()
	defer state.ResetForTesting()

	var mu sync.Mutex
	startedSessions := make(map[string]map[string]any)

	previousTransport := httptransport.MockTransport
	httptransport.MockTransport = mockRoundTripper(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()

		if r.URL.Path == "/api/v1/sessions/start" {
			bodyBytes, _ := io.ReadAll(r.Body)
			var payload map[string]any
			_ = json.Unmarshal(bodyBytes, &payload)
			sid, _ := payload["session_id"].(string)
			startedSessions[sid] = payload
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"status":"active","session_id":"` + sid + `"}`))),
			}, nil
		}
		if r.URL.Path == "/api/v1/sessions/prompt" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"status":"accepted"}`))),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
		}, nil
	})
	t.Cleanup(func() { httptransport.MockTransport = previousTransport })

	sessionID := "sess-vscode-chat-" + time.Now().Format("150405.000")
	cleanupSessionMarker(sessionID, 0)
	defer cleanupSessionMarker(sessionID, 0)

	// Step 1: Simulate first event being UserPromptSubmit (e.g. user sends message in VS Code chat)
	err := EnsureSessionStarted(sessionID, "copilot", 8888, "Explain this code")
	if err != nil {
		t.Fatalf("Auto-session start on chat prompt failed: %v", err)
	}

	mu.Lock()
	record, exists := startedSessions[sessionID]
	mu.Unlock()

	if !exists {
		t.Fatalf("Session %s was not registered with control plane on chat prompt", sessionID)
	}
	if record["app_id"] != "copilot" {
		t.Errorf("Expected app_id copilot, got %v", record["app_id"])
	}

	// Step 2: Now simulate first tool use in another fresh session
	freshSessionID := "sess-vscode-tool-" + time.Now().Format("150405.000")
	cleanupSessionMarker(freshSessionID, 0)
	defer cleanupSessionMarker(freshSessionID, 0)

	err = EnsureSessionStarted(freshSessionID, "antigravity", 7777, "")
	if err != nil {
		t.Fatalf("Auto-session start on tool use failed: %v", err)
	}

	mu.Lock()
	record2, exists2 := startedSessions[freshSessionID]
	mu.Unlock()

	if !exists2 {
		t.Fatalf("Session %s was not registered with control plane on preToolExecution", freshSessionID)
	}
	if record2["app_id"] != "antigravity" {
		t.Errorf("Expected app_id antigravity, got %v", record2["app_id"])
	}
}
