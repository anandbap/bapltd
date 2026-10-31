package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/internal/httptransport"
)

type e2eTransport func(*http.Request) (*http.Response, error)

func (f e2eTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Invoked by the control-plane E2E harness with its temporary loopback URL.
func TestAuditDeliveryEndToEnd(t *testing.T) {
	url := os.Getenv("BAP_TELEMETRY_E2E_URL")
	if url == "" {
		t.Skip("run the control-plane TestTelemetryDeliveryEndToEnd harness")
	}
	previousClient := httpClient
	defer func() { httpClient = previousClient }()
	previous := httptransport.MockTransport
	httptransport.MockTransport = e2eTransport(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+os.Getenv("BAP_TELEMETRY_E2E_PROOF"))
		return http.DefaultTransport.RoundTrip(r)
	})
	t.Cleanup(func() { httptransport.MockTransport = previous })
	httpClient = httptransport.New(3 * time.Second)
	for _, key := range []string{"BAP_TEST_MODE", "LTD_TEST", "BAP_ENV", "BAP_RETAIN_LOCAL"} {
		t.Setenv(key, "")
	}
	dir := t.TempDir()
	logPath, policyPath := filepath.Join(dir, "jsonl"), filepath.Join(dir, "policy.cedar")
	if err := os.WriteFile(policyPath, []byte("// isolated E2E policy location"), 0600); err != nil {
		t.Fatal(err)
	}
	entry := AuditEntry{EventID: "telemetry-e2e-event", SessionID: "telemetry-e2e", Source: "claude-code", Decision: "deny", FullCommand: "blocked-e2e-operation", Timestamp: time.Now().UTC()}
	if err := Log(&entry, logPath); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := Transmit(entry, url, logPath); ok {
		t.Fatal("rejected upload acknowledged")
	} else {
		t.Logf("rejected upload retained: %v", err)
	}
	if entries, err := ReadEntries(logPath); err != nil || len(entries) != 1 {
		t.Fatalf("rejected upload lost: %v %v", entries, err)
	}
	if n, err := FlushOfflineAudit(url, logPath); err != nil || n != 1 {
		t.Fatalf("retry failed: %d %v", n, err)
	}
	if entries, err := ReadEntries(logPath); err != nil || len(entries) != 0 {
		t.Fatalf("verified retry still queued: %v %v", entries, err)
	}
	if ok, _, err := Transmit(entry, url, logPath); !ok || err != nil {
		t.Fatalf("duplicate retry not acknowledged: %v %v", ok, err)
	}

	// The accepted ledger is intentionally lost, just as with an ephemeral deploy.
	transportClient := httptransport.New(3 * time.Second)
	restart, _ := http.NewRequest("POST", url+"/e2e/restart", nil)
	response, err := transportClient.Do(restart)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("restart failed")
	}
	response, err = transportClient.Get(url + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if n, err := FlushOfflineAudit(url, logPath); err != nil || n < 1 {
		t.Fatalf("acknowledged event was not recovered after restart: %d %v", n, err)
	}
	if n, err := FlushOfflineAudit(url, logPath); err != nil || n != 0 {
		t.Fatalf("recovery cursor replayed events repeatedly: %d %v", n, err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for _, frozen := range []bool{true, false} {
		action := "unfreeze"
		if frozen {
			action = "freeze"
		}
		body, _ := json.Marshal(map[string]string{"target": "telemetry-e2e", "scope": "session", "action": action})
		req, _ := http.NewRequest("POST", url+"/api/v1/control/agent/kill", bytes.NewReader(body))
		req.Header.Set("X-BAP-Admin-Token", "e2e-admin")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s failed: %d", action, resp.StatusCode)
		}
		resp, err = client.Get(url + "/api/v1/control/revocations")
		if err != nil {
			t.Fatal(err)
		}
		var state map[string]any
		err = json.NewDecoder(resp.Body).Decode(&state)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(state)
		if err := os.WriteFile(filepath.Join(dir, "policy-state.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		err = authz.CheckSessionRevocation(policyPath, "telemetry-e2e")
		if (err != nil) != frozen {
			t.Fatalf("edge enforcement mismatch frozen=%v: %v", frozen, err)
		}
	}
}
