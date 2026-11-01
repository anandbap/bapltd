package cmd

import (
	discoverymeta "bap-edge/internal/discovery"
	"bap-edge/internal/state"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiscoveryWorkerWithoutAnyAgentSessions(t *testing.T) {
	root := t.TempDir()
	t.Setenv("BAP_STATE_DIR", root)
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	delivered := make(chan int64, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report discoverymeta.Report
		if json.NewDecoder(r.Body).Decode(&report) != nil {
			w.WriteHeader(400)
			return
		}
		delivered <- report.Epoch
		json.NewEncoder(w).Encode(map[string]any{"status": "acknowledged", "run_id": report.RunID, "durable": false})
	}))
	defer server.Close()
	daemon := &DaemonServer{state: DaemonState{ServerURL: server.URL}, discoveryRequests: make(chan int64, 1), discoveryCollect: func(epoch int64) discoverymeta.Report {
		return discoverymeta.Collect([]discoverymeta.ConfigSource{{Path: filepath.Join(root, "absent.json"), Client: "claude-code"}}, epoch)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); daemon.runDiscoveryWorker(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case epoch := <-delivered:
		if epoch != 0 {
			t.Fatal(epoch)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no independent startup scan")
	}
	daemon.requestDiscovery(123)
	select {
	case epoch := <-delivered:
		if epoch != 123 {
			t.Fatal(epoch)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("on-demand scan required an agent session")
	}
	if len(daemon.sessions) != 0 {
		t.Fatal("scan fabricated agent sessions")
	}
}

func TestDiscoveryOfflineRetryAndNonDurableReplay(t *testing.T) {
	root := t.TempDir()
	r := discoverymeta.Collect([]discoverymeta.ConfigSource{{Path: filepath.Join(root, "absent.json"), Client: "claude-code"}}, 123)
	if err := discoverymeta.Queue(root, r); err != nil {
		t.Fatal(err)
	}
	mode := "offline"
	deliveries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		deliveries++
		var report discoverymeta.Report
		json.NewDecoder(req.Body).Decode(&report)
		if report.RunID != r.RunID {
			t.Error("retry changed run ID")
		}
		switch mode {
		case "offline":
			w.WriteHeader(503)
		case "bad-ack":
			json.NewEncoder(w).Encode(map[string]any{"status": "acknowledged", "run_id": "wrong"})
		default:
			json.NewEncoder(w).Encode(map[string]any{"status": "acknowledged", "run_id": report.RunID, "durable": false})
		}
	}))
	defer server.Close()
	for _, value := range []string{"offline", "bad-ack"} {
		mode = value
		if flushDiscovery(context.Background(), root, server.URL) == nil {
			t.Fatal("unacknowledged report consumed")
		}
		if _, err := os.Stat(filepath.Join(root, "pending", r.RunID+".json")); err != nil {
			t.Fatal(err)
		}
	}
	mode = "ok"
	if err := flushDiscovery(context.Background(), root, server.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "retained", r.RunID+".json")); err != nil {
		t.Fatal("non-durable ACK deleted local copy")
	}
	if err := replayDiscovery(root); err != nil {
		t.Fatal(err)
	}
	if err := flushDiscovery(context.Background(), root, server.URL); err != nil {
		t.Fatal(err)
	}
	if deliveries != 4 {
		t.Fatal(deliveries)
	}
}
