package hitl

import (
	"encoding/json"
	"fmt"
	"time"
)

// Checkpoint excludes signing material. Execution-grant epochs intentionally change on restart.
type checkpointState struct {
	Requests map[string]*EscalationRequest
	Recent   map[string]time.Time
	Attempts map[string]int
}

func (s *EscalationManager) MarshalCheckpoint() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(checkpointState{
		Requests: s.requests,
		Recent:   s.recentAttempts,
		Attempts: s.taskAttemptCounts,
	})
}

func (s *EscalationManager) RestoreCheckpoint(raw []byte) error {
	var state checkpointState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Requests == nil {
		return fmt.Errorf("invalid hitl checkpoint: missing Requests")
	}
	if state.Recent == nil {
		return fmt.Errorf("invalid hitl checkpoint: missing Recent")
	}
	if state.Attempts == nil {
		return fmt.Errorf("invalid hitl checkpoint: missing Attempts")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = state.Requests
	s.recentAttempts = state.Recent
	s.taskAttemptCounts = state.Attempts

	return nil
}
