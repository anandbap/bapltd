package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/discovery"
)

// A configured SQL failure must not quietly become a successful memory ACK.
// Explicit test/development memory mode remains advertised as non-durable.
func (s *Server) SetDiscoveryStorageError(err error) {
	if err != nil {
		s.inventoryErr = err
	}
}

func (s *Server) discoveryReady(w http.ResponseWriter) bool {
	if s.inventory == nil || s.inventoryErr != nil {
		writeError(w, 503, "Discovery storage unavailable; no in-memory fallback")
		return false
	}
	return true
}
func strictDiscoveryJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, 400, "Invalid discovery payload or unsupported fields")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, 400, "Exactly one JSON object required")
		return false
	}
	return true
}
func (s *Server) handleDiscoveryReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "Method not allowed")
		return
	}
	claims, err := s.workstationIdentity(r)
	if err != nil {
		writeError(w, 401, "Valid enrolled workstation proof required")
		return
	}
	if !s.discoveryReady(w) {
		return
	}
	var report discovery.Report
	if !strictDiscoveryJSON(w, r, &report) {
		return
	}
	if err := discovery.ValidateReport(report); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	duplicate, err := s.inventory.Ingest(claims.InstanceID, claims.UserEmail, report)
	if errors.Is(err, discovery.ErrConflict) {
		writeError(w, 409, err.Error())
		return
	}
	if err != nil {
		writeError(w, 503, "Discovery report could not be committed")
		return
	}
	if s.auditStore != nil {
		_, _ = s.auditStore.Ingest([]audit.Event{{
			EventID:     "discovery-ingest-" + report.RunID,
			Source:      "controlplane-discovery",
			Executable:  "discovery.scan",
			Decision:    "acknowledged",
			FullCommand: "DISCOVERY_REPORT_RECEIVED instance=" + claims.InstanceID + " run_id=" + report.RunID,
			Reason:      "Discovery report received and acknowledged for workstation " + claims.InstanceID,
			Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		}})
	}
	writeJSON(w, 200, map[string]any{
		"status":         "acknowledged",
		"run_id":         report.RunID,
		"duplicate":      duplicate,
		"durable":        false,
		"server_epoch":   s.serverEpoch,
		"storage":        s.inventory.Storage(),
		"instance_id":    claims.InstanceID,
		"received_at":    time.Now().UTC().Format(time.RFC3339),
		"findings_count": len(report.Observations),
	})
}
func (s *Server) handleDiscoveryTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "Method not allowed")
		return
	}
	if !s.discoveryReady(w) {
		return
	}
	var req struct {
		Scope     string   `json:"scope"`
		Instances []string `json:"instances"`
	}
	if !strictDiscoveryJSON(w, r, &req) {
		return
	}
	if req.Scope == "selected" {
		known := map[string]bool{}
		for _, a := range s.registry.List() {
			known[a.InstanceID] = true
		}
		for _, id := range req.Instances {
			if !known[id] {
				writeError(w, 400, "Selected workstation is not enrolled in the registry")
				return
			}
		}
	}
	epoch, err := s.inventory.Trigger(req.Scope, req.Instances)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_, _ = s.auditStore.Ingest([]audit.Event{{EventID: "discovery-trigger-" + strconv.FormatInt(epoch, 10), Source: "controlplane-discovery", Executable: "discovery.rescan", Decision: "queued", FullCommand: "Requested " + req.Scope + " discovery rescan", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}})
	writeJSON(w, 202, map[string]any{"status": "queued", "scan_epoch": epoch, "scope": req.Scope, "message": "Workstation completion has not yet been reported"})
}
func (s *Server) handleDiscoveryFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "Method not allowed")
		return
	}
	if !s.discoveryReady(w) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	revision, err := strconv.ParseUint(q.Get("revision"), 10, 64)
	if q.Get("revision") != "" && err != nil {
		writeError(w, 400, "Invalid snapshot revision")
		return
	}
	p, err := s.inventory.List(q.Get("instance_id"), q.Get("kind"), q.Get("state"), q.Get("cursor"), limit, revision)
	if err != nil {
		writeError(w, 409, "Inventory changed; refresh the list before continuing")
		return
	}
	writeJSON(w, 200, p)
}
func (s *Server) handleDiscoveryReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "Method not allowed")
		return
	}
	if !s.discoveryReady(w) {
		return
	}
	reports := s.inventory.Reports()
	filtered := make([]discovery.ScanState, 0, 100)
	for _, report := range reports {
		if instance := r.URL.Query().Get("instance_id"); instance != "" && report.InstanceID != instance {
			continue
		}
		if len(filtered) < 100 {
			filtered = append(filtered, report)
		}
	}
	writeJSON(w, 200, map[string]any{"reports": filtered, "count": len(filtered), "total": len(reports), "storage": s.inventory.Storage(), "durable": false})
}
func (s *Server) handleDiscoverySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "Method not allowed")
		return
	}
	if !s.discoveryReady(w) {
		return
	}
	seen := map[string]bool{}
	var expected []string
	for _, a := range s.registry.List() {
		if a.InstanceID != "" && !seen[a.InstanceID] {
			seen[a.InstanceID] = true
			expected = append(expected, a.InstanceID)
		}
	}
	writeJSON(w, 200, s.inventory.Summary(expected))
}
func (s *Server) handleDiscoveryDisposition(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "Method not allowed")
		return
	}
	if !s.discoveryReady(w) {
		return
	}
	var req struct {
		ID        string     `json:"id"`
		State     string     `json:"state"`
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !strictDiscoveryJSON(w, r, &req) {
		return
	}
	if err := s.inventory.Disposition(req.ID, req.State, req.Reason, req.ExpiresAt); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_, _ = s.auditStore.Ingest([]audit.Event{{EventID: "discovery-disposition-" + strconv.FormatInt(time.Now().UnixNano(), 10), Source: "controlplane-discovery", Executable: "discovery.disposition", Decision: req.State, FullCommand: "Discovery asset " + req.ID, Reason: req.Reason, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}})
	writeJSON(w, 200, map[string]any{"status": "recorded", "id": req.ID, "state": req.State})
}
func (s *Server) discoveryEpoch(r *http.Request, id string) int64 {
	if s.inventory == nil {
		return 0
	}
	if claims, err := s.workstationIdentity(r); err == nil {
		return s.inventory.EpochFor(claims.InstanceID)
	}
	if sess, err := s.sessionStore.GetSummary(id); err == nil {
		return s.inventory.EpochFor(sess.InstanceID)
	}
	if a, err := s.registry.Get(id); err == nil {
		return s.inventory.EpochFor(a.InstanceID)
	}
	return 0
}
