package registry

import "bap-controlplane/pkg/types"

// The index avoids a fleet-wide scan on every authenticated heartbeat. Status
// changes remain visible because index entries refer to the canonical records.
func (s *Store) WorkstationBlocked(instance, app string, includeQuarantine bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buildIdentityIndexLocked()
	hasActive := false
	isBlocked := false
	for _, a := range s.identityIndex[instance+"\x00"+app] {
		if a.Status == types.StatusActive {
			hasActive = true
			break
		}
		if primary := s.agents[a.SupersededBy]; primary != nil && primary.InstanceID == instance && primary.AppID == app && primary.Status == types.StatusActive {
			hasActive = true
			break
		}
		if a.Status == types.StatusRevoked || a.Status == types.StatusDeregistered || (includeQuarantine && a.Status == types.StatusQuarantined) {
			isBlocked = true
		}
	}
	if hasActive {
		return false
	}
	return isBlocked
}

func (s *Store) buildIdentityIndexLocked() {
	if s.identityIndex != nil {
		return
	}
	s.identityIndex = make(map[string][]*types.RegisteredAgent)
	for _, a := range s.agents {
		s.indexIdentityLocked(a)
	}
}

func (s *Store) indexIdentityLocked(a *types.RegisteredAgent) {
	if s.identityIndex == nil || a.InstanceID == "" {
		return
	}
	for _, key := range []string{a.InstanceID + "\x00" + a.AppID, "instance\x00" + a.InstanceID} {
		list := s.identityIndex[key]
		found := false
		for i, existing := range list {
			if existing.AgentID == a.AgentID {
				list[i] = a
				found = true
				break
			}
		}
		if !found {
			list = append(list, a)
		}
		s.identityIndex[key] = list
	}
}

func (s *Store) removeIdentityLocked(a *types.RegisteredAgent) {
	if s.identityIndex == nil || a.InstanceID == "" {
		return
	}
	for _, key := range []string{a.InstanceID + "\x00" + a.AppID, "instance\x00" + a.InstanceID} {
		list := s.identityIndex[key]
		for i, existing := range list {
			if existing.AgentID == a.AgentID {
				list = append(list[:i], list[i+1:]...)
				break
			}
		}
		s.identityIndex[key] = list
	}
}
