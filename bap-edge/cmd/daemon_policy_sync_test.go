package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"bap-edge/internal/httptransport"
	"bap-edge/internal/policystore"
	"bap-edge/internal/state"
)

func TestDaemonStartsPolicySyncWithoutSessionWatcher(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	previous := httptransport.MockTransport
	var changed atomic.Bool
	httptransport.MockTransport = heartbeatTransport(func(r *http.Request) (*http.Response, error) {
		body := `{}`
		if r.URL.Path == "/api/v1/policy/sync" {
			body = `{"directive":"UPDATE_REQUIRED","bundle":{"version":41,"policy_cedar":"permit(principal, action, resource);"}}`
			if changed.Load() {
				body = `{"directive":"UPDATE_REQUIRED","bundle":{"version":42,"policy_cedar":"permit(principal, action, resource);","kill_switch":true}}`
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	t.Cleanup(func() { httptransport.MockTransport = previous })
	s, err := NewDaemonServer("http://localhost:8080", 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.runPolicySyncWorker(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("daemon did not stop")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := policystore.New(policystore.DefaultPolicyDir()).LoadState()
		if err == nil && st.Version == 41 {
			changed.Store(true)
		}
		if err == nil && st.Version == 42 && st.KillSwitch {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("daemon failed to sync kill switch without a session watcher")
}

func TestDaemonHeartbeatFlushesPromptSpoolWithoutWatcher(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()
	t.Cleanup(state.ResetForTesting)
	previous := httptransport.MockTransport
	defer func() { httptransport.MockTransport = previous }()
	posted := false
	httptransport.MockTransport = heartbeatTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/sessions/prompt" {
			posted = true
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":"alive"}`))}, nil
	})
	if err := os.MkdirAll(promptSpoolDir(), 0700); err != nil {
		t.Fatal(err)
	}
	path := promptSpoolDir() + string(os.PathSeparator) + "pending.json"
	raw, _ := json.Marshal(map[string]any{"session_id": "session", "body": map[string]any{"session_id": "session", "user_prompt": "Review changes"}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s := &DaemonServer{state: DaemonState{ServerURL: "http://localhost:8080"}, sessions: map[string]AttachedSession{"session": {SessionID: "session"}}}
	s.pulseAttachedSessions(t.Context(), httptransport.New(time.Second))
	if !posted {
		t.Fatal("daemon did not replay pending prompt")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("acknowledged prompt was not removed")
	}
}
