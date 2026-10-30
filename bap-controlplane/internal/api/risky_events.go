package api

import (
	"net/http"
	"strconv"
	"strings"

	"bap-controlplane/internal/audit"
)

// Pages a stable snapshot of the retained ledger, filtering before pagination.
func (s *Server) handleRiskyAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	events := s.auditStore.List(0)
	q := r.URL.Query()
	snapshot, offset, limit := len(events), 0, 100
	for key, dest := range map[string]*int{"snapshot": &snapshot, "offset": &offset, "limit": &limit} {
		if raw := q.Get(key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 || (key == "limit" && (n == 0 || n > 500)) {
				writeError(w, http.StatusBadRequest, "Invalid "+key)
				return
			}
			*dest = n
		}
	}
	if snapshot > len(events) {
		writeError(w, http.StatusConflict, "Audit snapshot expired; reload the list")
		return
	}
	risky := make([]audit.Event, 0)
	for i := snapshot - 1; i >= 0; i-- {
		ev := events[i]
		d := strings.ToLower(ev.Decision)
		if strings.Contains(d, "deny") || strings.Contains(d, "denied") || strings.Contains(d, "block") || strings.Contains(d, "audit_permitted") || strings.Contains(d, "shadow") {
			risky = append(risky, ev)
		}
	}
	if offset > len(risky) {
		offset = len(risky)
	}
	end := offset + limit
	if end > len(risky) {
		end = len(risky)
	}
	s.writeTelemetry(w, r, map[string]any{"events": risky[offset:end], "count": end - offset,
		"total": len(risky), "snapshot": snapshot, "next_offset": end, "has_more": end < len(risky)})
}
