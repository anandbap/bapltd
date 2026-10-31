package session

// Reporting layers describe received evidence, never authorization or proof
// that all operations on the workstation are intercepted. The set is bounded.
func addReportingLayer(sess *Session, layer string) {
	switch layer {
	case "hook", "mcp", "shim", "broker", "gateway", "discovery", "launcher", "sdk":
	default:
		return
	}
	for _, existing := range sess.ReportingLayers {
		if existing == layer {
			return
		}
	}
	// Copy on update: summary snapshots must not share mutable slice backing arrays.
	sess.ReportingLayers = append(append([]string(nil), sess.ReportingLayers...), layer)
}

func (s *Store) RecordReportingLayer(id, layer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess := s.sessions[id]; sess != nil {
		addReportingLayer(sess, layer)
		s.saveSessionToDB(sess)
	}
}
