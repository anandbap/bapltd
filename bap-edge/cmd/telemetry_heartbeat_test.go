package cmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type heartbeatTransport func(*http.Request) (*http.Response, error)

func (f heartbeatTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type heartbeatBody struct {
	io.Reader
	closed *atomic.Int64
}

func (b heartbeatBody) Close() error { b.closed.Add(1); return nil }

func TestDaemonHeartbeatsAreConcurrentAndDoNotHoldSessionLock(t *testing.T) {
	s := &DaemonServer{state: DaemonState{ServerURL: "http://controlplane.test"}, sessions: map[string]AttachedSession{
		"a": {SessionID: "a"}, "b": {SessionID: "b"},
	}}
	entered, release := make(chan struct{}, 2), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var closed atomic.Int64
	client := &http.Client{Transport: heartbeatTransport(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Body: heartbeatBody{strings.NewReader(`{"status":"ok"}`), &closed}, Header: make(http.Header)}, nil
	})}
	done := make(chan struct{})
	go func() { s.pulseAttachedSessions(ctx, client); close(done) }()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("session heartbeats were serialized")
		}
	}
	lockAcquired := make(chan struct{})
	go func() { s.mu.Lock(); s.mu.Unlock(); close(lockAcquired) }()
	select {
	case <-lockAcquired:
	case <-time.After(time.Second):
		t.Fatal("network request held session lock")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat cycle did not finish")
	}
	if closed.Load() != 2 || s.heartbeatSuccess != 2 {
		t.Fatalf("responses not closed or accounted: %d %d", closed.Load(), s.heartbeatSuccess)
	}
}

func TestPulseHeartbeatDoesNotTreatErrorsAsSuccess(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{{503, `{"status":"error"}`}, {200, "invalid JSON"}, {200, `{"status":"error"}`}} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			if status, _, _ := pulseHeartbeat(server.URL, "session"); status != "" {
				t.Fatalf("failed heartbeat reported %q", status)
			}
		})
	}
}
