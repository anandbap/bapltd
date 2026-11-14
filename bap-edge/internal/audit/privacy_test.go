package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetadataAuditSpoolAndRetryContainNoCommandOrPrompt(t *testing.T) {
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	t.Setenv("BAP_TEST_MODE", "")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	entry := AuditEntry{EventID: "metadata-event", FullCommand: "echo PRIVATE_CODE", UserPrompt: "PRIVATE_PROMPT", Arguments: "--token=PRIVATE_TOKEN", Reason: "PRIVATE_REASON", CanonicalAction: "dev:go:test", Decision: "allow"}
	if err := Log(&entry, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE_") || entry.PromptHash == "" {
		t.Fatal("private content persisted or correlation hash missing")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []map[string]any
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			t.Error(err)
		}
		encoded, _ := json.Marshal(events)
		if strings.Contains(string(encoded), "PRIVATE_") || len(events) != 1 || events[0]["event_id"] != "metadata-event" || events[0]["canonical_action"] != "dev:go:test" {
			t.Errorf("unexpected payload: %s", encoded)
		}
		_, _ = w.Write([]byte(`{"chain_valid":true,"status":"acknowledged","ingested":1,"durable":true}`))
	}))
	defer server.Close()
	if n, err := FlushOfflineAudit(server.URL, path); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	// Old backlog created before the privacy change is filtered again before transmission.
	legacy := AuditEntry{EventID: "metadata-event", FullCommand: "echo PRIVATE_LEGACY", UserPrompt: "PRIVATE_LEGACY_PROMPT", CanonicalAction: "dev:go:test"}
	if ok, _, err := Transmit(legacy, server.URL, ""); !ok || err != nil {
		t.Fatal(ok, err)
	}
}
