package policystore

import (
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrKillSwitchActive = errors.New("emergency kill-switch is active; all executions are blocked")
	ErrRollbackRejected = errors.New("policy rollback rejected: incoming version is older than cached version")
	ErrDigestMismatch   = errors.New("policy bundle integrity violation: rules digest does not match content")
	ErrNoPolicyFound    = errors.New("no policy found in cache or local search paths")
)

type Bundle struct {
	Version     uint64 `json:"version"`
	Digest      string `json:"digest"`
	PolicyCedar string `json:"policy_cedar"`
	SchemaJSON  string `json:"schema_json,omitempty"`
	KillSwitch  bool   `json:"kill_switch"`
	UpdatedAt   string `json:"updated_at"`
}

type PolicyState struct {
	Version    uint64    `json:"version"`
	Digest     string    `json:"digest"`
	KillSwitch bool      `json:"kill_switch"`
	LastSync   time.Time `json:"last_sync"`
}

type SyncResponse struct {
	Directive string  `json:"directive"`
	Bundle    *Bundle `json:"bundle,omitempty"`
}

type Store struct {
	directory string
}

// DefaultPolicyDir returns the cached policy directory in .bapstate/policy.
func DefaultPolicyDir() string {
	return state.PolicyDir()
}

func New(dir string) *Store {
	if dir == "" {
		dir = DefaultPolicyDir()
	}
	_ = os.MkdirAll(dir, 0700)
	return &Store{directory: dir}
}

func (s *Store) Directory() string {
	return s.directory
}

// ComputeDigest computes SHA-256 over cedarCode + schemaJSON
func ComputeDigest(cedarCode, schemaJSON string) string {
	h := sha256.New()
	h.Write([]byte(cedarCode))
	if schemaJSON != "" {
		h.Write([]byte(schemaJSON))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Accept stores and atomically updates the local policy cache
func (s *Store) Accept(bundle Bundle) error {
	computed := ComputeDigest(bundle.PolicyCedar, bundle.SchemaJSON)
	if bundle.Digest != "" && bundle.Digest != computed {
		return fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, bundle.Digest, computed)
	}

	current, err := s.LoadState()
	if err == nil && current.Version > 0 {
		if bundle.Version < current.Version {
			return ErrRollbackRejected
		}
	}

	// Write policy.cedar
	cedarPath := filepath.Join(s.directory, "policy.cedar")
	if err := os.WriteFile(cedarPath, []byte(bundle.PolicyCedar), 0600); err != nil {
		return fmt.Errorf("failed to write cached policy.cedar: %w", err)
	}

	// Write schema.json if present
	schemaPath := filepath.Join(s.directory, "schema.json")
	if bundle.SchemaJSON != "" {
		if err := os.WriteFile(schemaPath, []byte(bundle.SchemaJSON), 0600); err != nil {
			return fmt.Errorf("failed to write cached schema.json: %w", err)
		}
	}

	state := PolicyState{
		Version:    bundle.Version,
		Digest:     computed,
		KillSwitch: bundle.KillSwitch,
		LastSync:   time.Now().UTC(),
	}

	stateData, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	statePath := filepath.Join(s.directory, "policy-state.json")
	return os.WriteFile(statePath, stateData, 0600)
}

func (s *Store) LoadState() (PolicyState, error) {
	statePath := filepath.Join(s.directory, "policy-state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		return PolicyState{}, err
	}
	var state PolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return PolicyState{}, err
	}
	return state, nil
}

// Current returns the cached policy path and verifies kill-switch is not active
func (s *Store) Current() (string, string, PolicyState, error) {
	state, err := s.LoadState()
	if err != nil {
		return "", "", PolicyState{}, ErrNoPolicyFound
	}

	if state.KillSwitch {
		return "", "", state, ErrKillSwitchActive
	}

	cedarPath := filepath.Join(s.directory, "policy.cedar")
	if _, err := os.Stat(cedarPath); err != nil {
		return "", "", state, ErrNoPolicyFound
	}

	schemaPath := filepath.Join(s.directory, "schema.json")
	if _, err := os.Stat(schemaPath); err != nil {
		schemaPath = ""
	}

	return cedarPath, schemaPath, state, nil
}

// SyncWithServer calls bapcontrolplane /api/v1/policy/sync.
// If control plane is offline/down, it falls back to cached settings seamlessly.
func (s *Store) SyncWithServer(serverURL, agentID string, timeout time.Duration) (Bundle, bool, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	client := httptransport.New(timeout)
	state, _ := s.LoadState()

	reqPayload := map[string]any{
		"agent_id":          agentID,
		"installed_version": state.Version,
		"installed_digest":  state.Digest,
	}
	body, _ := json.Marshal(reqPayload)

	endpoint := fmt.Sprintf("%s/api/v1/policy/sync", serverURL)
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		// Control plane is offline / unreachable -> Fail-secure fallback to cached policy
		cedarPath, schemaPath, currentState, loadErr := s.Current()
		if loadErr != nil {
			return Bundle{}, true, fmt.Errorf("control plane unreachable and no valid local cache: %w (server err: %v)", loadErr, err)
		}
		cedarData, _ := os.ReadFile(cedarPath)
		schemaData, _ := os.ReadFile(schemaPath)
		return Bundle{
			Version:     currentState.Version,
			Digest:      currentState.Digest,
			PolicyCedar: string(cedarData),
			SchemaJSON:  string(schemaData),
			KillSwitch:  currentState.KillSwitch,
		}, true, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return Bundle{}, false, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	var syncResp SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return Bundle{}, false, fmt.Errorf("failed to parse sync response: %w", err)
	}

	if syncResp.Directive == "KILL_SWITCH" || (syncResp.Bundle != nil && syncResp.Bundle.KillSwitch) {
		// Persist kill-switch so it remains locked even offline
		_ = s.Accept(Bundle{
			Version:    state.Version,
			Digest:     state.Digest,
			KillSwitch: true,
		})
		return Bundle{}, false, ErrKillSwitchActive
	}

	if syncResp.Directive == "UPDATE_REQUIRED" && syncResp.Bundle != nil {
		if err := s.Accept(*syncResp.Bundle); err != nil {
			return Bundle{}, false, err
		}
		return *syncResp.Bundle, false, nil
	}

	// CURRENT: read current cached
	cedarPath, schemaPath, currentState, err := s.Current()
	if err != nil {
		return Bundle{}, false, err
	}
	cedarData, _ := os.ReadFile(cedarPath)
	schemaData, _ := os.ReadFile(schemaPath)
	return Bundle{
		Version:     currentState.Version,
		Digest:      currentState.Digest,
		PolicyCedar: string(cedarData),
		SchemaJSON:  string(schemaData),
	}, false, nil
}
