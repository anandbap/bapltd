package api

import (
	"bap-controlplane/internal/pilot"
	"io"
	"net/http"
	"time"
)

// ConfigurePilotRoster is startup-only: no client, heartbeat or admin read can
// change the expected denominator or convert this configuration into authority.
func (s *Server) ConfigurePilotRoster(reader io.Reader) error {
	roster, revision, err := pilot.Decode(reader)
	if err != nil {
		return err
	}
	s.pilotRoster, s.pilotRosterRevision = roster, revision
	return nil
}

func (s *Server) handlePilotCoverage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeError(w, 405, "Method not allowed")
		return
	}
	if s.pilotRoster == nil {
		writeError(w, 503, "Pilot roster not configured; reporting denominator unknown")
		return
	}
	ids := make([]string, 0, len(s.pilotRoster.Entries))
	for _, e := range s.pilotRoster.Entries {
		ids = append(ids, e.InstanceID)
	}
	writeJSON(w, 200, pilot.Evaluate(s.pilotRoster, s.pilotRosterRevision, time.Now(), s.registry.ReportingCheckins(ids)))
}
