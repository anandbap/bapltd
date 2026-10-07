package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"bap-edge/internal/audit"
)

func TestDaemonPrivilegeAndModeDetection(t *testing.T) {
	server, err := NewDaemonServer("http://localhost:8080", 0)
	if err != nil {
		t.Fatalf("NewDaemonServer failed: %v", err)
	}

	// In test runner / non-elevated user context:
	if isElevated() {
		if server.state.Privilege != "ELEVATED_ADMIN" {
			t.Errorf("expected ELEVATED_ADMIN, got %s", server.state.Privilege)
		}
		if server.state.OperatingMode != "OPTIMAL" {
			t.Errorf("expected OPTIMAL, got %s", server.state.OperatingMode)
		}
		if !server.state.Capabilities.KernelEBPFETW {
			t.Errorf("expected KernelEBPFETW true when elevated")
		}
	} else {
		if server.state.Privilege != "STANDARD_USER" {
			t.Errorf("expected STANDARD_USER in unprivileged context, got %s", server.state.Privilege)
		}
		if server.state.OperatingMode != "DEGRADED" {
			t.Errorf("expected DEGRADED mode in unprivileged context, got %s", server.state.OperatingMode)
		}
		if server.state.Capabilities.KernelEBPFETW {
			t.Errorf("expected KernelEBPFETW false in degraded user mode")
		}
		if server.state.Capabilities.KernelPacketFilter {
			t.Errorf("expected KernelPacketFilter false in degraded user mode")
		}
		// Core user-space capabilities must remain active in degraded mode
		if !server.state.Capabilities.IPCHub {
			t.Errorf("expected IPCHub true in degraded mode")
		}
		if !server.state.Capabilities.BackgroundSpool {
			t.Errorf("expected BackgroundSpool true in degraded mode")
		}
		if !server.state.Capabilities.JobObjectContainment {
			t.Errorf("expected JobObjectContainment true in degraded mode")
		}
	}
}

func TestDaemonIPCEndpoints(t *testing.T) {
	server, err := NewDaemonServer("http://localhost:8080", 0)
	if err != nil {
		t.Fatalf("NewDaemonServer failed: %v", err)
	}

	// 1. Test /health
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	server.handleHealth(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/health status = %d, want 200", w.Code)
	}
	var healthResp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&healthResp)
	if healthResp["status"] != "healthy" {
		t.Errorf("health status = %v, want 'healthy'", healthResp["status"])
	}

	// 2. Test /api/v1/daemon/attach and /api/v1/daemon/detach
	attachPayload := map[string]any{
		"session_id": "test-sess-100",
		"app_id":     "payment-app",
		"pid":        os.Getpid(),
	}
	body, _ := json.Marshal(attachPayload)
	reqAttach := httptest.NewRequest("POST", "/api/v1/daemon/attach", bytes.NewReader(body))
	wAttach := httptest.NewRecorder()
	server.handleAttach(wAttach, reqAttach)
	if wAttach.Code != http.StatusOK {
		t.Errorf("/api/v1/daemon/attach status = %d, want 200", wAttach.Code)
	}

	server.mu.RLock()
	sess, exists := server.sessions["test-sess-100"]
	server.mu.RUnlock()
	if !exists || sess.AppID != "payment-app" {
		t.Errorf("session was not registered in daemon map")
	}

	// 3. Test /api/v1/daemon/status
	reqStatus := httptest.NewRequest("GET", "/status", nil)
	wStatus := httptest.NewRecorder()
	server.handleStatus(wStatus, reqStatus)
	if wStatus.Code != http.StatusOK {
		t.Errorf("/status status = %d, want 200", wStatus.Code)
	}
	var statusResp struct {
		Daemon struct {
			Mode     string `json:"mode"`
			Degraded bool   `json:"degraded"`
		} `json:"daemon"`
		AgentsAttached struct {
			Count int `json:"count"`
		} `json:"agents_attached"`
		Telemetry struct {
			MessagesReceived int64 `json:"messages_received"`
		} `json:"telemetry"`
	}
	if err := json.NewDecoder(wStatus.Body).Decode(&statusResp); err != nil {
		t.Fatalf("failed to decode /status JSON: %v", err)
	}
	if statusResp.AgentsAttached.Count != 1 {
		t.Errorf("expected 1 attached agent in status, got %d", statusResp.AgentsAttached.Count)
	}

	// 4. Test /api/v1/daemon/event ingestion
	eventEntry := audit.AuditEntry{
		EventID:     "evt-test-123",
		SessionID:   "test-sess-100",
		Executable:  "git",
		FullCommand: "git status",
		Decision:    "allow",
		Timestamp:   time.Now().UTC(),
	}
	eventBody, _ := json.Marshal(eventEntry)
	reqEvent := httptest.NewRequest("POST", "/api/v1/daemon/event", bytes.NewReader(eventBody))
	wEvent := httptest.NewRecorder()
	server.handleEvent(wEvent, reqEvent)
	if wEvent.Code != http.StatusOK {
		t.Errorf("/api/v1/daemon/event status = %d, want 200", wEvent.Code)
	}

	if server.messagesRecv != 1 {
		t.Errorf("expected messagesRecv == 1, got %d", server.messagesRecv)
	}

	// 5. Test detach
	detachPayload := map[string]any{"session_id": "test-sess-100"}
	detachBody, _ := json.Marshal(detachPayload)
	reqDetach := httptest.NewRequest("POST", "/api/v1/daemon/detach", bytes.NewReader(detachBody))
	wDetach := httptest.NewRecorder()
	server.handleDetach(wDetach, reqDetach)
	if wDetach.Code != http.StatusOK {
		t.Errorf("/api/v1/daemon/detach status = %d, want 200", wDetach.Code)
	}

	server.mu.RLock()
	_, stillExists := server.sessions["test-sess-100"]
	server.mu.RUnlock()
	if stillExists {
		t.Errorf("expected session to be detached from daemon")
	}
}
