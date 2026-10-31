package cmd

import (
	"context"
	"sync/atomic"

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
			if ok && err == nil {
				atomic.AddInt64(&s.transSuccess, 1)
			} else {
				atomic.AddInt64(&s.transFailed, 1)
			}
		}
	}
}
