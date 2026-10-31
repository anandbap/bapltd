package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bap-edge/internal/httptransport"
)

// Session liveness is independent of slow health probes and revocation syncs.
func (s *DaemonServer) runSessionHeartbeatWorker(ctx context.Context) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	client := httptransport.New(2 * time.Second)
	for {
		if s.state.ServerURL != "" {
			s.pulseAttachedSessions(ctx, client)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func closeHeartbeatResponse(resp *http.Response) {
	// Drain small acknowledgements to reuse connections, then always close.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

func (s *DaemonServer) pulseAttachedSessions(ctx context.Context, client *http.Client) {
	s.mu.RLock()
	sessions := make([]AttachedSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.RUnlock()
	jobs := make(chan AttachedSession)
	var workers sync.WaitGroup
	count := len(sessions)
	if count > 8 {
		count = 8
	}
	for i := 0; i < count; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for sess := range jobs {
				body, _ := json.Marshal(map[string]any{"session_id": sess.SessionID, "app_id": sess.AppID, "pid": sess.PID})
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.state.ServerURL, "/")+"/api/v1/sessions/heartbeat", bytes.NewReader(body))
				if err != nil {
					atomic.AddInt64(&s.heartbeatFailed, 1)
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&s.heartbeatFailed, 1)
					continue
				}
				var ack struct {
					Status string `json:"status"`
				}
				valid := resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&ack) == nil
				if valid && (ack.Status == "alive" || ack.Status == "ok" || ack.Status == "active" || ack.Status == "revoked" || ack.Status == "closed" || ack.Status == "quarantined") {
					atomic.AddInt64(&s.heartbeatSuccess, 1)
				} else {
					atomic.AddInt64(&s.heartbeatFailed, 1)
				}
				closeHeartbeatResponse(resp)
			}
		}()
	}
	for _, sess := range sessions {
		select {
		case jobs <- sess:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return
		}
	}
	close(jobs)
	workers.Wait()
}
