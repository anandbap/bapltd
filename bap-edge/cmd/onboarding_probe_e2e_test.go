package cmd

import (
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeWireAgainstControlPlane(t *testing.T) {
	endpoint, proof := os.Getenv("BAP_PROBE_E2E_URL"), os.Getenv("BAP_PROBE_E2E_PROOF")
	if endpoint == "" {
		t.Skip("run control-plane probe E2E harness")
	}
	root := t.TempDir()
	t.Setenv("BAP_STATE_DIR", root)
	t.Setenv("BAP_SERVER_URL", endpoint)
	t.Setenv("BAP_CREDENTIALS", filepath.Join(root, "absent.json"))
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	previous := httptransport.MockTransport
	httptransport.MockTransport = heartbeatTransport(func(request *http.Request) (*http.Response, error) {
		request = request.Clone(request.Context())
		request.Header.Set("Authorization", "Bearer "+proof)
		return http.DefaultTransport.RoundTrip(request)
	})
	t.Cleanup(func() { httptransport.MockTransport = previous })
	start := time.Now().UTC().Add(-5 * time.Second)
	probe := onboardingProbe{ID: strings.Repeat("a", 32), StartedAt: start, ExpiresAt: start.Add(15 * time.Minute)}
	if err := writeRuntimeState(probeStatePath(), probe); err != nil {
		t.Fatal(err)
	}
	sid := "probe-wire-session"
	sum := sha256.Sum256([]byte(sid))
	reference := hex.EncodeToString(sum[:])
	for i, event := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "Stop"} {
		if err := writeRuntimeState(filepath.Join(root, "reporting-health", "claude-code-"+event+".json"), map[string]any{"app": "claude-code", "event": event, "observed_at": start.Add(time.Duration(i+1) * time.Second), "source": "native_callback", "session_reference": reference, "probe_id": probe.ID}); err != nil {
			t.Fatal(err)
		}
	}
	if err := RunOnboarding([]string{"check", "--require"}); err == nil {
		t.Fatal("local metadata alone qualified reporting")
	}
	client := httptransport.New(3 * time.Second)
	post := func(path string, value any) {
		body, _ := json.Marshal(value)
		response, err := client.Post(endpoint+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			var failure any
			json.NewDecoder(response.Body).Decode(&failure)
			t.Fatalf("%s: %d %v", path, response.StatusCode, failure)
		}
	}
	post("/api/v1/sessions/start", map[string]any{"session_id": sid, "app_id": "claude-code", "instance_id": "probe-wire-machine"})
	text := "BAP-ONBOARDING-" + probe.ID
	hash := sha256.Sum256([]byte(text))
	post("/api/v1/sessions/prompt", map[string]any{"session_id": sid, "producer": "claude-lifecycle-hook", "user_prompt": text, "prompt_hash": hex.EncodeToString(hash[:]), "prompt_capture_enabled": true, "intent": map[string]any{"primary": "TEST_VERIFICATION", "confidence": 1, "classifier_version": "fixture", "source": "claude-user-prompt-submit", "prompt_captured": true}})
	post("/api/v1/audit/ingest", []map[string]any{{"event_id": "probe-wire-policy", "session_id": sid, "source": "claude-code", "reporting_layer": "broker", "full_command": "git status", "decision": "allow", "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}})
	if err := RunOnboarding([]string{"check", "--require"}); err != nil {
		t.Fatal("owned prompt/policy/local callback protocol did not correlate", err)
	}
	// A second fresh probe can qualify public synthetic prompt metadata without
	// uploading prompt text. The first probe's policy record must not suffice.
	probe.ID = strings.Repeat("b", 32)
	probe.StartedAt = time.Now().UTC()
	probe.ExpiresAt = probe.StartedAt.Add(15 * time.Minute)
	if err := writeRuntimeState(probeStatePath(), probe); err != nil {
		t.Fatal(err)
	}
	for i, event := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "Stop"} {
		if err := writeRuntimeState(filepath.Join(root, "reporting-health", "claude-code-"+event+".json"), map[string]any{"app": "claude-code", "event": event, "observed_at": probe.StartedAt.Add(time.Duration(i+1) * time.Millisecond), "source": "native_callback", "session_reference": reference, "probe_id": probe.ID}); err != nil {
			t.Fatal(err)
		}
	}
	text = "BAP-ONBOARDING-" + probe.ID + " Please run git status in this fixture repository, then describe the result."
	hash = sha256.Sum256([]byte(text))
	post("/api/v1/sessions/prompt", map[string]any{"session_id": sid, "producer": "claude-lifecycle-hook", "prompt_hash": hex.EncodeToString(hash[:]), "prompt_capture_enabled": false, "intent": map[string]any{"primary": "TEST_VERIFICATION", "confidence": 1, "classifier_version": "fixture", "source": "claude-user-prompt-submit", "prompt_captured": false}})
	if err := RunOnboarding([]string{"check", "--require"}); err == nil {
		t.Fatal("prior probe's policy record was reused")
	}
	post("/api/v1/audit/ingest", []map[string]any{{"event_id": "probe-wire-policy-hash-only", "session_id": sid, "source": "claude-code", "reporting_layer": "broker", "full_command": "git status", "decision": "allow", "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}})
	if err := RunOnboarding([]string{"check", "--require"}); err != nil {
		t.Fatal("hash-only public probe did not correlate", err)
	}
}
