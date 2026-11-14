package policy

import (
	"bap-controlplane/pkg/types"
	"encoding/json"
	"fmt"
)

// Checkpoint excludes signing material. Execution-grant epochs intentionally change on restart.
type checkpointState struct {
	Bundle          Bundle
	Tiers           map[types.RiskTier]Bundle
	Overrides       map[string]AssetOverride
	Assets          map[string]string
	Effects         map[string][]string
	Recommendations []Recommendation
}

// UseCheckpointPersistence disables legacy per-setting file writes once the server's atomic
// authority checkpoint owns durability. Two independently failing stores must not disagree on
// whether a recommendation decision was committed.
func (s *Store) UseCheckpointPersistence() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settingsPath = ""
}

func (s *Store) MarshalCheckpoint() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	overrides := s.assetOverrides
	if overrides == nil {
		overrides = map[string]AssetOverride{}
	}
	assets := s.enrolledAssets
	if assets == nil {
		assets = map[string]string{}
	}
	effects := s.approvedEffects
	if effects == nil {
		effects = map[string][]string{}
	}
	return json.Marshal(checkpointState{
		Bundle:          s.bundle,
		Tiers:           s.tierBundles,
		Overrides:       overrides,
		Assets:          assets,
		Effects:         effects,
		Recommendations: s.recommendations,
	})
}

func (s *Store) RestoreCheckpoint(raw []byte) error {
	var state checkpointState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Tiers == nil {
		return fmt.Errorf("invalid policy checkpoint: missing Tiers")
	}
	if state.Overrides == nil {
		return fmt.Errorf("invalid policy checkpoint: missing Overrides")
	}
	if state.Assets == nil {
		return fmt.Errorf("invalid policy checkpoint: missing Assets")
	}
	if state.Effects == nil {
		return fmt.Errorf("invalid policy checkpoint: missing Effects")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle = state.Bundle
	s.tierBundles = state.Tiers
	s.assetOverrides = state.Overrides
	s.enrolledAssets = state.Assets
	s.approvedEffects = state.Effects
	s.recommendations = state.Recommendations

	return nil
}
