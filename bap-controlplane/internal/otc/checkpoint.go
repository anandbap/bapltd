package otc

import (
	"encoding/json"
	"fmt"
)

// Checkpoint excludes signing material. Execution-grant epochs intentionally change on restart.
type checkpointState struct {
	Tokens map[string]*TokenEntry
}

func (s *Store) MarshalCheckpoint() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(checkpointState{
		Tokens: s.tokens,
	})
}

func (s *Store) RestoreCheckpoint(raw []byte) error {
	var state checkpointState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Tokens == nil {
		return fmt.Errorf("invalid otc checkpoint: missing Tokens")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = state.Tokens

	return nil
}
