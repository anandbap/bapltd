package registry

import "bap-controlplane/internal/pilot"

// ReportingCheckins reads only explicitly requested identities. It does not copy
// fleet histories, keys or session events, and cannot revive restricted agents.
func (s *Store) ReportingCheckins(instances []string) map[string][]pilot.Checkin {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buildIdentityIndexLocked()
	result := make(map[string][]pilot.Checkin, len(instances))
	for _, id := range instances {
		for _, a := range s.identityIndex["instance\x00"+id] {
			c := pilot.Checkin{OwnerEmail: a.OwnerEmail, Active: string(a.Status) == "active", RecoveryOnly: a.RecoveryOnly}
			if a.LastHeartbeatAt != nil {
				c.At = *a.LastHeartbeatAt
			}
			result[id] = append(result[id], c)
		}
	}
	return result
}
