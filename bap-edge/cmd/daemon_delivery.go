package cmd

import (
	"context"
	"sync/atomic"
	"time"

	"bap-edge/internal/audit"
)

func (s *DaemonServer) enqueueTelemetry(entry audit.AuditEntry) {
	select {
	case s.eventQueue <- entry:
	default: /* already persisted; spool retries */
	}
}

func (s *DaemonServer) runEventDeliveryWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-s.eventQueue:
			ok, _, err := audit.Transmit(entry, s.state.ServerURL, audit.DefaultLogPath())
			s.mu.Lock()
			s.lastAuditAttemptAt = time.Now().UTC()
			s.lastAuditResult = "retained_for_retry"
			if ok && err == nil {
				s.lastAuditUploadAt = s.lastAuditAttemptAt
				s.lastAuditResult = "acknowledged"
			}
			s.mu.Unlock()
			if ok && err == nil {
				atomic.AddInt64(&s.transSuccess, 1)
			} else {
				atomic.AddInt64(&s.transFailed, 1)
			}
		}
	}
}
