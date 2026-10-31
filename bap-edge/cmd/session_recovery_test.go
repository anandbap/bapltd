package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestMissingHeartbeatIsDistinctFromOutage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unknown session", 404) }))
	defer server.Close()
	status, _, _ := pulseHeartbeat(server.URL, "existing-claude")
	if status != "missing" {
		t.Fatalf("unknown session classified as %q", status)
	}
}

func TestSessionResumeUsesProofAndStableID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sessions/resume" || r.Header.Get("Authorization") != "Bearer proof" {
			t.Error("missing resume proof")
		}
		var body sessionResumePayload
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.SessionID != "stable-session" || body.InstanceID != "machine" {
			t.Error("session identity changed")
		}
		_, _ = w.Write([]byte(`{"status":"active"}`))
	}))
	defer server.Close()
	status, err := postSessionResume(context.Background(), server.Client(), server.URL, sessionResumePayload{SessionID: "stable-session", InstanceID: "machine", AppID: "claude-code", ClientPID: os.Getpid()}, "proof")
	if err != nil || status != "ok" {
		t.Fatalf("resume failed: %s %v", status, err)
	}
}

func TestEmptyRestartStateCannotClearCachedRestrictions(t *testing.T) {
	existing := map[string]any{"kill_switch": true, "frozen": true, "revoked_sessions": []string{"blocked"}}
	data := remoteRevocations{RecoveryProtocol: 1}
	merged := mergeRevocationCache(existing, data, []string{"machine"})
	if merged["kill_switch"] != true || merged["frozen"] != true || !hasTarget(merged["revoked_sessions"].([]string), []string{"blocked"}) {
		t.Fatal("restart erased restrictions")
	}
	data.FleetRestored = true
	data.RestoredAgents = []string{"machine"}
	data.RestoredSessions = []string{"blocked"}
	merged = mergeRevocationCache(merged, data, []string{"machine"})
	if merged["kill_switch"] != false || merged["frozen"] != false || len(merged["revoked_sessions"].([]string)) != 0 {
		t.Fatal("explicit administrative restore was ignored")
	}
}

func TestRevocationCacheWriteRemainsReadableAcrossUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.json")
	for i := 0; i < 2; i++ {
		if err := writeRevocationCache(path, remoteRevocations{RecoveryProtocol: 1, RevokedSessions: []string{"blocked"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid cache file")
	}
}
