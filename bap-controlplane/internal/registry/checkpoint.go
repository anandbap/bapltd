package registry

import (
	"bap-controlplane/pkg/types"
	"encoding/json"
	"fmt"
)

// Checkpoint excludes signing material. Execution-grant epochs intentionally change on restart.
type checkpointState struct {
	Agents map[string]*types.RegisteredAgent
}

func (s *Store) MarshalCheckpoint() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(checkpointState{
		Agents: s.agents,
	})
}

func (s *Store) RestoreCheckpoint(raw []byte) error {
	var state checkpointState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Agents == nil {
		return fmt.Errorf("invalid registry checkpoint: missing Agents")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents = state.Agents
	s.identityIndex = nil
	return nil
}
