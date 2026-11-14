package session

import (
	"bap-controlplane/pkg/types"
	"encoding/json"
	"fmt"
)

// Checkpoint excludes signing material. Execution-grant epochs intentionally change on restart.
type checkpointState struct {
	Sessions          map[string]*Session
	Order             []string
	RevokedUsers      map[string]bool
	IntentCounts      map[string]int
	TotalPrompts      int
	Prompts           []PromptRecord
	Principals        map[string]*types.AgentPrincipal
	SessionPrincipals map[string]string
}

func (s *Store) MarshalCheckpoint() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sessions := make(map[string]*Session, len(s.sessions))
	for id, current := range s.sessions {
		copy := *current
		copy.Events = nil
		sessions[id] = &copy
	}
	return json.Marshal(checkpointState{
		Sessions:          sessions,
		Order:             s.order,
		RevokedUsers:      s.revokedUsers,
		IntentCounts:      s.intentCounts,
		TotalPrompts:      s.totalPrompts,
		Prompts:           s.prompts,
		Principals:        s.principals,
		SessionPrincipals: s.sessionPrincipals,
	})
}

func (s *Store) RestoreCheckpoint(raw []byte) error {
	var state checkpointState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Sessions == nil {
		return fmt.Errorf("invalid session checkpoint: missing Sessions")
	}
	if state.RevokedUsers == nil {
		return fmt.Errorf("invalid session checkpoint: missing RevokedUsers")
	}
	if state.IntentCounts == nil {
		return fmt.Errorf("invalid session checkpoint: missing IntentCounts")
	}
	if state.Principals == nil {
		return fmt.Errorf("invalid session checkpoint: missing Principals")
	}
	if state.SessionPrincipals == nil {
		return fmt.Errorf("invalid session checkpoint: missing SessionPrincipals")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = state.Sessions
	s.order = state.Order
	s.revokedUsers = state.RevokedUsers
	s.intentCounts = state.IntentCounts
	s.totalPrompts = state.TotalPrompts
	s.prompts = state.Prompts
	s.principals = state.Principals
	s.sessionPrincipals = state.SessionPrincipals

	return nil
}
