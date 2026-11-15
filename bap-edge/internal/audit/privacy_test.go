package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bap-edge/internal/httptransport"
)

func TestLocalAuditRetainsEvidenceWhileMetadataSyncAndRetryOmitContent(t *testing.T) {
	for _, inherited := range []string{"default", "LTD_TEST", "BAP_ENV", "BAP_RETAIN_LOCAL"} {
		t.Run(inherited, func(t *testing.T) {
			if inherited != "default" {
				value := "1"
				if inherited == "BAP_ENV" {
					value = "test"
				}
				t.Setenv(inherited, value)
			}
			testLocalAuditCaptureAndMetadataDelivery(t)
		})
	}
}

func testLocalAuditCaptureAndMetadataDelivery(t *testing.T) {
	t.Helper()
	t.Setenv("BAP_TELEMETRY_CONTENT", "")
	// Exercise actual delivery and archive creation, independently of test-mode
	// and retention flags inherited from a developer shell or CI runner.
	for _, key := range []string{"BAP_TEST_MODE", "LTD_TEST", "BAP_ENV", "BAP_RETAIN_LOCAL"} {
		t.Setenv(key, "")
	}
	prev := httptransport.PromptContentProvider
	httptransport.PromptContentProvider = func() bool { return false } // admin turned prompt reporting off
	defer func() { httptransport.PromptContentProvider = prev }()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	entry := AuditEntry{EventID: "metadata-event", FullCommand: "echo PRIVATE_CODE", UserPrompt: "PRIVATE_PROMPT", Arguments: "--token=PRIVATE_TOKEN", Reason: "PRIVATE_REASON", CanonicalAction: "dev:go:test", Decision: "allow"}
	entry.ToolInput = json.RawMessage(`{"command":"echo PRIVATE_INPUT","token":"PRIVATE_TOKEN"}`)
	if err := Log(&entry, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "PRIVATE_CODE") || !strings.Contains(string(raw), "PRIVATE_REASON") || !strings.Contains(string(raw), "PRIVATE_PROMPT") || strings.Contains(string(raw), "PRIVATE_TOKEN") || entry.PromptHash == "" || entry.ContentHash == "" {
		t.Fatal("local evidence lost, secret not redacted, or correlation hash missing")
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
		t.Fatalf("metadata flush delivered %d events, want 1: %v", n, err)
	}
	retained, err := os.ReadFile(archivePath(server.URL, path))
	if err != nil || !strings.Contains(string(retained), "PRIVATE_CODE") || !strings.Contains(string(retained), "PRIVATE_REASON") {
		t.Fatalf("durable metadata sync destroyed local evidence: %s %v", retained, err)
	}
	// Old backlog created before the privacy change is filtered again before transmission.
	legacy := AuditEntry{EventID: "metadata-event", FullCommand: "echo PRIVATE_LEGACY", UserPrompt: "PRIVATE_LEGACY_PROMPT", CanonicalAction: "dev:go:test"}
	if ok, _, err := Transmit(legacy, server.URL, ""); !ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestStructuredLocalToolInputIsHashProtected(t *testing.T) {
	entry := AuditEntry{ToolInput: json.RawMessage(`{"pattern":"*.go"}`)}
	before := ComputeEntryHash(entry, "previous")
	entry.ToolInput = json.RawMessage(`{ "pattern": "*.go" }`)
	if before != ComputeEntryHash(entry, "previous") {
		t.Fatal("JSON whitespace changed hash")
	}
	entry.ToolInput = json.RawMessage(`{"pattern":"*.py"}`)
	if before == ComputeEntryHash(entry, "previous") {
		t.Fatal("tool input tampering was not detected")
	}
}
