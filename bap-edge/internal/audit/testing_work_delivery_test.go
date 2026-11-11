package audit

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

func TestEngineeringTestCommandsDeliveredImmediatelyAndAfterOffline(t *testing.T) {
	for _, key := range []string{"BAP_TEST_MODE", "LTD_TEST", "BAP_ENV", "BAP_RETAIN_LOCAL"} {
		t.Setenv(key, "")
	}
	for _, command := range []string{"go test ./...", "pytest tests/unit -q", "python -m pytest tests", "python test_leak.py", "npm test"} {
		t.Run(command, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			entry := AuditEntry{EventID: "engineering-tests", Source: "latest-test-agent", FullCommand: command, Decision: "allow", Timestamp: time.Now().UTC()}
			if err := Log(&entry, path); err != nil {
				t.Fatal(err)
			}
			var reject atomic.Bool
			reject.Store(true)
			var received atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				var events []map[string]any
				if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
					t.Error(err)
				}
				if len(events) != 1 || events[0]["full_command"] != command || events[0]["event_id"] != entry.EventID {
					t.Errorf("testing evidence changed: %v", events)
				}
				if reject.Load() {
					w.WriteHeader(503)
					return
				}
				w.Write([]byte(`{"chain_valid":true,"status":"acknowledged","ingested":1,"durable":true}`))
			}))
			defer server.Close()
			if ok, _, err := Transmit(entry, server.URL, path); ok || err != nil {
				t.Fatalf("offline: %v %v", ok, err)
			}
			if entries, _ := ReadEntries(path); len(entries) != 1 {
				t.Fatal("offline test evidence discarded")
			}
			reject.Store(false)
			if count, err := FlushOfflineAudit(server.URL, path); err != nil || count != 1 {
				t.Fatalf("replay: %d %v", count, err)
			}
			if err := Log(&entry, path); err != nil {
				t.Fatal(err)
			}
			if ok, _, err := Transmit(entry, server.URL, path); !ok || err != nil {
				t.Fatalf("live testing suppressed: %v %v", ok, err)
			}
			if got := received.Load(); got != 3 {
				t.Fatalf("not every delivery attempted: %d", got)
			}
		})
	}
}

func TestEnrollmentPreventsTestEnvironmentFromSuppressingDelivery(t *testing.T) {
	t.Setenv("BAP_TEST_MODE", "1")
	root := t.TempDir()
	t.Setenv("BAP_CREDENTIALS", filepath.Join(root, "identity-fixture.json"))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte(`{"chain_valid":true,"status":"acknowledged","ingested":1,"durable":true}`))
	}))
	defer server.Close()
	fixture, _ := json.Marshal(map[string]string{"server_url": server.URL, "session_token": "synthetic-enrollment-fixture", "instance_id": "fixture-machine"})
	if err := os.WriteFile(filepath.Join(root, "identity-fixture.json"), fixture, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "audit.jsonl")
	entry := AuditEntry{EventID: "enrolled-testing", Source: "test-agent", FullCommand: "go test ./...", Timestamp: time.Now().UTC()}
	if err := Log(&entry, path); err != nil {
		t.Fatal(err)
	}
	if ok, reason, err := Transmit(entry, server.URL, path); !ok || err != nil {
		t.Fatal("test environment disabled enrolled reporting", reason, err)
	}
	if err := Log(&entry, path); err != nil {
		t.Fatal(err)
	}
	if count, err := FlushOfflineAudit(server.URL, path); count != 1 || err != nil {
		t.Fatal(count, err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatal("missing enrolled reports", got)
	}
}

func TestExplicitTestModePreservesQueuedEvidenceWithoutDelivery(t *testing.T) {
	t.Setenv("BAP_TEST_MODE", "1")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	entry := AuditEntry{EventID: "isolated-test", Source: "claude-code", FullCommand: "go test ./...", Timestamp: time.Now().UTC()}
	if err := Log(&entry, path); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("explicit test mode contacted a control plane") }))
	defer server.Close()
	if ok, reason, err := Transmit(entry, server.URL, path); ok || reason != "skipped_test_mode" || err != nil {
		t.Fatal(ok, reason, err)
	}
	if count, err := FlushOfflineAudit(server.URL, path); count != 0 || err != nil {
		t.Fatal(count, err)
	}
	if entries, _ := ReadEntries(path); len(entries) != 1 {
		t.Fatal("test isolation deleted evidence")
	}
}
