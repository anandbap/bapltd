package governance

import (
	"bap-controlplane/pkg/types"
	"encoding/json"
	"fmt"
)

// Checkpoint excludes signing material. Execution-grant epochs intentionally change on restart.
type checkpointState struct {
	Proposals map[string]*types.ActionProposal
}

func (s *Store) MarshalCheckpoint() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(checkpointState{
		Proposals: s.proposals,
	})
}

func (s *Store) RestoreCheckpoint(raw []byte) error {
	var state checkpointState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Proposals == nil {
		return fmt.Errorf("invalid governance checkpoint: missing Proposals")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proposals = state.Proposals

	return nil
}
