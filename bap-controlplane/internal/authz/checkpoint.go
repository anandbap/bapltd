package authz

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

func (s *TokenMinter) CheckpointIdentity() string {
	return fmt.Sprintf("%x", sha256.Sum256(s.signingKey))
}

// Checkpoint excludes signing material. Execution-grant epochs intentionally change on restart.
type checkpointState struct {
	Revoked      map[string]string
	Workstations map[string]string
}

func (s *TokenMinter) MarshalCheckpoint() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(checkpointState{
		Revoked:      s.revokedGrants,
		Workstations: s.workstationGrants,
	})
}

func (s *TokenMinter) RestoreCheckpoint(raw []byte) error {
	var state checkpointState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Revoked == nil {
		return fmt.Errorf("invalid authz checkpoint: missing Revoked")
	}
	if state.Workstations == nil {
		return fmt.Errorf("invalid authz checkpoint: missing Workstations")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedGrants = state.Revoked
	s.workstationGrants = state.Workstations

	return nil
}
