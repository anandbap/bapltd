package cmd

import (
	discoverymeta "bap-edge/internal/discovery"
	"bap-edge/internal/httptransport"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiscoveryAgainstControlPlane(t *testing.T) {
	url, proof := os.Getenv("BAP_DISCOVERY_E2E_URL"), os.Getenv("BAP_DISCOVERY_E2E_PROOF")
	if url == "" {
		t.Skip("run control-plane discovery E2E harness")
	}
	previous := httptransport.MockTransport
	httptransport.MockTransport = heartbeatTransport(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+proof)
		return http.DefaultTransport.RoundTrip(r)
	})
	t.Cleanup(func() { httptransport.MockTransport = previous })
	root := t.TempDir()
	path := filepath.Join(root, ".mcp.json")
	os.WriteFile(path, []byte(`{"mcpServers":{"one":{"command":"node","args":["PRIVATE-SYNTHETIC-INPUT"]},"two":{"url":"https://example.invalid"}}}`), 0600)
	report := discoverymeta.Collect([]discoverymeta.ConfigSource{{Path: path, Client: "claude-code"}}, 42)
	if len(report.Observations) != 2 {
		t.Fatal(report)
	}
	journal := filepath.Join(root, "journal")
	if err := discoverymeta.Queue(journal, report); err != nil {
		t.Fatal(err)
	}
	if err := flushDiscovery(context.Background(), journal, url); err == nil {
		t.Fatal("temporary failure was not retained")
	}
	if err := flushDiscovery(context.Background(), journal, url); err != nil {
		t.Fatal(err)
	}
	client := httptransport.New(time.Second)
	req, _ := http.NewRequest("POST", url+"/e2e/restart", nil)
	req.Header.Set("Authorization", "Bearer "+proof)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if err := replayDiscovery(journal); err != nil {
		t.Fatal(err)
	}
	if err := flushDiscovery(context.Background(), journal, url); err != nil {
		t.Fatal(err)
	}
}
