package policystore

import (
	"bap-edge/internal/authz"
	"bap-edge/internal/httptransport"
	"bap-edge/internal/state"
	"bap-edge/pkg/version"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrKillSwitchActive = errors.New("emergency kill-switch is active; all executions are blocked")
	ErrRollbackRejected = errors.New("policy rollback rejected: incoming version is older than cached version")
	ErrDigestMismatch   = errors.New("policy bundle integrity violation: rules digest does not match content")
	ErrNoPolicyFound    = errors.New("no policy found in cache or local search paths")
)

type Bundle struct {
	Version               uint64 `json:"version"`
	Digest                string `json:"digest"`
	Signature             string `json:"signature,omitempty"`
	PolicyCedar           string `json:"policy_cedar"`
	SchemaJSON            string `json:"schema_json,omitempty"`
	KillSwitch            bool   `json:"kill_switch"`
	StrictToolEnforcement bool   `json:"strict_tool_enforcement"`
	EnforcementTier       string `json:"enforcement_tier,omitempty"`
	UpdatedAt             string `json:"updated_at"`

	// Control-plane-managed enforcement setting (signed): plain read-only inspection inside
	// the workspace needs no task grant.
	ZSPReadExempt bool `json:"zsp_read_exempt"`

	// Asset-scoped Ed25519 signature over all of the above (see trust.go).
	AssetID          string `json:"asset_id,omitempty"`
	SigAlg           string `json:"sig_alg,omitempty"`
	KeyID            string `json:"key_id,omitempty"`
	SignatureEd25519 string `json:"signature_ed25519,omitempty"`

	// KeyChain: rotation links (each signed by the previous key) leading to KeyID.
	KeyChain []rotationLink `json:"key_chain,omitempty"`
}

type PolicyState struct {
	Version               uint64    `json:"version"`
	Digest                string    `json:"digest"`
	Signature             string    `json:"signature,omitempty"`
	KillSwitch            bool      `json:"kill_switch"`
	StrictToolEnforcement bool      `json:"strict_tool_enforcement"`
	EnforcementTier       string    `json:"enforcement_tier,omitempty"`
	LastSync              time.Time `json:"last_sync"`

	UpdatedAt        string `json:"updated_at,omitempty"`
	ZSPReadExempt    bool   `json:"zsp_read_exempt"`
	AssetID          string `json:"asset_id,omitempty"`
	SigAlg           string `json:"sig_alg,omitempty"`
	KeyID            string `json:"key_id,omitempty"`
	SignatureEd25519 string `json:"signature_ed25519,omitempty"`
}

// asBundle rebuilds the signed fields of a cached state for verification.
func (st PolicyState) asBundle() Bundle {
	return Bundle{
		Version: st.Version, Digest: st.Digest, KillSwitch: st.KillSwitch,
		StrictToolEnforcement: st.StrictToolEnforcement, EnforcementTier: st.EnforcementTier,
		UpdatedAt: st.UpdatedAt, ZSPReadExempt: st.ZSPReadExempt,
		AssetID: st.AssetID, SigAlg: st.SigAlg, KeyID: st.KeyID, SignatureEd25519: st.SignatureEd25519,
	}
}

type SyncResponse struct {
	Directive      string  `json:"directive"`
	Bundle         *Bundle `json:"bundle,omitempty"`
	ServerVersion  string  `json:"server_version,omitempty"`
	MinEdgeVersion string  `json:"min_edge_version,omitempty"`
	Message        string  `json:"message,omitempty"`
}

type Store struct {
	directory  string
	signingKey []byte
	assetID    string
	authToken  string
}

// SetAuthToken makes this store authenticate its syncs with an explicit enrollment credential
// instead of looking one up at the default location. Enrollment uses it: `register --config <path>`
// saves credentials somewhere else, and an unauthenticated sync would be issued a bundle for no
// asset, which a freshly pinned machine rightly rejects.
func (s *Store) SetAuthToken(tok string) { s.authToken = tok }

func (s *Store) credential() string {
	if s.authToken != "" {
		return s.authToken
	}
	return currentCredential()
}

// SetAssetID overrides the machine identity the store binds signed policy to (tests).
func (s *Store) SetAssetID(id string) { s.assetID = id }

// AssetID is the machine identity this store's signed rules must be issued for: the asset bound
// by the authenticated enrollment (recorded in the pin), else the hardware-derived id.
func (s *Store) AssetID() string {
	if s.assetID != "" {
		return s.assetID
	}
	if pin, ok := s.LoadPin(); ok {
		return pin.AssetID // "" for machines pinned by first contact: they receive fleet bundles
	}
	return ResolveAssetID()
}

// requestAssetID is what this machine reports to the control plane (used at enrollment and for
// legacy binding); the control plane derives the authoritative asset from the credential.
func (s *Store) requestAssetID() string {
	if s.assetID != "" {
		return s.assetID
	}
	return ResolveAssetID()
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

func (s *Store) SetSigningKey(key []byte) {
	s.signingKey = key
}

// VerifyBundleSignature validates that the bundle's signature matches the expected HMAC-SHA256 signature
func VerifyBundleSignature(version uint64, digest string, killSwitch bool, signature string, key []byte) bool {
	if len(key) == 0 {
		return true // Unmanaged or dev mode
	}
	if signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, key)
	payload := fmt.Sprintf("bap-policy-v1:%d:%s:%t", version, digest, killSwitch)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}

// ComputeDigest computes SHA-256 over cedarCode + schemaJSON
func ComputeDigest(cedarCode, schemaJSON string) string {
	return authz.ComputePolicyDigest(cedarCode, schemaJSON)
}

// Accept stores and atomically updates the local policy cache
func (s *Store) Accept(bundle Bundle) error {
	computed := ComputeDigest(bundle.PolicyCedar, bundle.SchemaJSON)
	if bundle.Digest != "" && bundle.Digest != computed {
		return fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, bundle.Digest, computed)
	}

	if len(s.signingKey) > 0 && !VerifyBundleSignature(bundle.Version, computed, bundle.KillSwitch, bundle.Signature, s.signingKey) {
		return fmt.Errorf("%w: policy bundle cryptographic signature verification failed (forged or unauthenticated bundle)", ErrDigestMismatch)
	}

	// Managed machine (a control-plane key is pinned): only a bundle signed by that key,
	// for THIS asset, covering every enforcement flag, may change the rules.
	if pin, managed := s.LoadPin(); managed {
		// Follow an authorised key rotation (chain signed by the key we already trust).
		if np, moved := s.followRotation(pin, bundle); moved {
			pin = np
		}
		// Machines pinned by first contact before enrollment binding existed adopt their asset on the
		// first authenticated sync, but only for a bundle that verifies under the key they pinned.
		if pin.AssetID == "" && s.assetID == "" && bundle.AssetID != "" && s.credential() != "" &&
			verifyBundleAgainstPin(pin, bundle.AssetID, bundle, computed) == nil {
			pin.AssetID = bundle.AssetID
			_ = s.writePin(pin)
		}
		if err := verifyBundleAgainstPin(pin, s.AssetID(), bundle, computed); err != nil {
			return err
		}
	}

	// Rollback protection only counts a cached version that itself verifies. A tampered state
	// (for example one whose version was bumped to block re-issue) must not be able to veto
	// the control plane's signed correction.
	current, err := s.LoadState()
	if err == nil && current.Version > 0 && s.cachedStateVerifies(current) {
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
		Version:               bundle.Version,
		Digest:                computed,
		Signature:             bundle.Signature,
		KillSwitch:            bundle.KillSwitch,
		StrictToolEnforcement: bundle.StrictToolEnforcement,
		EnforcementTier:       bundle.EnforcementTier,
		LastSync:              time.Now().UTC(),
		UpdatedAt:             bundle.UpdatedAt,
		ZSPReadExempt:         bundle.ZSPReadExempt,
		AssetID:               bundle.AssetID,
		SigAlg:                bundle.SigAlg,
		KeyID:                 bundle.KeyID,
		SignatureEd25519:      bundle.SignatureEd25519,
	}

	stateData, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	statePath := filepath.Join(s.directory, "policy-state.json")
	if err := os.WriteFile(statePath, stateData, 0600); err != nil {
		return err
	}
	// The signed record lives in its own file. Older bapedge builds (and other components) rewrite
	// policy-state.json with a struct that has no signature fields; keeping the signature there
	// would make every mixed-version machine fail verification.
	if state.SigAlg != "" {
		return s.writeSignedRecord(state)
	}
	return nil
}

func (s *Store) signedPath() string { return filepath.Join(s.directory, "policy-signed.json") }

func (s *Store) writeSignedRecord(st PolicyState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.signedPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.signedPath())
}

// LoadState returns the cached policy state. When a signed record exists it is authoritative for
// every enforcement field (the legacy policy-state.json is only consulted for LastSync), so a
// rewrite of the legacy file by an older build can neither break nor change signed rules.
func (s *Store) LoadState() (PolicyState, error) {
	statePath := filepath.Join(s.directory, "policy-state.json")
	data, legacyErr := os.ReadFile(statePath)
	var state PolicyState
	if legacyErr == nil {
		if err := json.Unmarshal(data, &state); err != nil {
			legacyErr = err
		}
	}
	if !s.Managed() {
		// Unmanaged (no pinned key): legacy semantics, nothing is signed.
		if legacyErr != nil {
			return PolicyState{}, legacyErr
		}
		return state, nil
	}
	if sdata, err := os.ReadFile(s.signedPath()); err == nil {
		var signed PolicyState
		if json.Unmarshal(sdata, &signed) == nil {
			if legacyErr == nil && state.LastSync.After(signed.LastSync) {
				signed.LastSync = state.LastSync
			}
			return signed, nil
		}
		return PolicyState{}, fmt.Errorf("signed policy record is unreadable")
	}
	if legacyErr != nil {
		return PolicyState{}, legacyErr
	}
	return state, nil
}

// Current returns the cached policy path and verifies kill-switch is not active
// and cryptographic SHA-256 digest integrity is intact.
// If the cache directory is uninitialized, it falls back to checking local search paths.
func (s *Store) Current() (string, string, PolicyState, error) {
	state, err := s.LoadState()
	pin, managed := s.LoadPin()
	if managed && err != nil {
		// A machine that has been enrolled must always have signed state. Deleting it must not
		// downgrade the machine to an unsigned local policy file.
		return "", "", PolicyState{}, fmt.Errorf("%w: signed policy state is missing or unreadable (%v)", ErrPolicyTampered, err)
	}
	if err == nil {
		if managed {
			if vErr := verifyBundleAgainstPin(pin, s.AssetID(), state.asBundle(), state.Digest); vErr != nil {
				return "", "", state, vErr
			}
		}
		if state.KillSwitch {
			return "", "", state, ErrKillSwitchActive
		}

		cedarPath := filepath.Join(s.directory, "policy.cedar")
		if data, err := os.ReadFile(cedarPath); err == nil {
			schemaPath := filepath.Join(s.directory, "schema.json")
			var schemaData []byte
			if sData, sErr := os.ReadFile(schemaPath); sErr == nil {
				schemaData = sData
			} else {
				schemaPath = ""
			}

			// Cryptographic anti-tamper verification
			if state.Digest != "" {
				computed := ComputeDigest(string(data), string(schemaData))
				if computed != state.Digest && ComputeDigest(string(data), "") != state.Digest {
					return "", "", state, fmt.Errorf("%w: cached policy.cedar has been tampered with or modified locally (expected %s, got %s)", ErrDigestMismatch, state.Digest, computed)
				}
				if len(s.signingKey) > 0 && state.Signature != "" {
					if !VerifyBundleSignature(state.Version, state.Digest, state.KillSwitch, state.Signature, s.signingKey) {
						return "", "", state, fmt.Errorf("%w: cached policy bundle cryptographic signature invalid or forged (possible offline tampering)", ErrDigestMismatch)
					}
				}
			}

			return cedarPath, schemaPath, state, nil
		}
	}

	if managed {
		// Signed state exists but the cached policy file is gone: fail closed, never fall back.
		return "", "", state, fmt.Errorf("%w: cached policy.cedar is missing", ErrPolicyTampered)
	}

	// Fallback: search canonical release and candidate paths
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "policy.cedar"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "bin", "policy.cedar"),
			filepath.Join(home, ".local", "bin", "policy.cedar"),
		)
	}
	candidates = append(candidates,
		"policy.cedar",
		filepath.Join("bap-edge", "policy.cedar"),
		filepath.Join("..", "policy.cedar"),
	)
	if ws := authz.GetWorkspaceRoot(); ws != "" {
		candidates = append(candidates,
			filepath.Join(ws, "policy.cedar"),
			filepath.Join(ws, "bap-edge", "policy.cedar"),
		)
	}

	for _, cand := range candidates {
		data, err := os.ReadFile(cand)
		if err == nil && len(data) > 0 {
			schemaPath := filepath.Join(filepath.Dir(cand), "schema.json")
			var schemaData []byte
			if sData, sErr := os.ReadFile(schemaPath); sErr == nil {
				schemaData = sData
			} else {
				schemaPath = ""
			}
			computed := ComputeDigest(string(data), string(schemaData))
			bundle := Bundle{
				Version:     1,
				Digest:      computed,
				PolicyCedar: string(data),
				SchemaJSON:  string(schemaData),
				KillSwitch:  false,
			}
			_ = s.Accept(bundle)

			return cand, schemaPath, PolicyState{
				Version:    1,
				Digest:     computed,
				KillSwitch: false,
				LastSync:   time.Now().UTC(),
			}, nil
		}
	}

	return "", "", PolicyState{}, ErrNoPolicyFound
}

// SyncWithServer calls bapcontrolplane /api/v1/policy/sync.
// If control plane is offline/down, it falls back to cached settings seamlessly.
func (s *Store) SyncWithServer(serverURL, agentID string, timeout time.Duration) (Bundle, bool, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	// This machine enrolled with one control plane. Any other server (a local test instance, a
	// look-alike) is never consulted: the cached signed rules stay in force and a tampered cache
	// still fails closed.
	if s.foreignServer(serverURL) {
		cedarPath, schemaPath, cur, err := s.Current()
		if err != nil {
			return Bundle{}, true, err
		}
		cedarData, _ := os.ReadFile(cedarPath)
		schemaData, _ := os.ReadFile(schemaPath)
		return Bundle{Version: cur.Version, Digest: cur.Digest, PolicyCedar: string(cedarData), SchemaJSON: string(schemaData), KillSwitch: cur.KillSwitch}, true, nil
	}

	client := httptransport.New(timeout)
	state, _ := s.LoadState()
	// (Managed only: on an unmanaged store Current() adopts local fallback policy files as a side
	// effect, which must not happen as part of building a sync request.)
	if s.Managed() {
		if _, _, _, cerr := s.Current(); errors.Is(cerr, ErrPolicyTampered) {
			// Our cache does not verify: claim to hold nothing so the control plane re-issues a
			// freshly signed bundle instead of answering CURRENT.
			state = PolicyState{}
		}
	}

	reqPayload := map[string]any{
		"asset_id":           s.requestAssetID(),
		"agent_id":           agentID,
		"installed_version":  state.Version,
		"installed_digest":   state.Digest,
		"installed_key_id":   state.KeyID,
		"installed_asset_id": state.AssetID,
		"agent_version":      version.Version,
	}
	body, _ := json.Marshal(reqPayload)

	endpoint := fmt.Sprintf("%s/api/v1/policy/sync", serverURL)
	httpReq, errReq := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if errReq != nil {
		return Bundle{}, false, errReq
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-BAP-Agent-Version", version.Version)
	if tok := s.credential(); tok != "" {
		// The control plane derives this machine's asset from the enrolled credential, never from the body.
		httpReq.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := client.Do(httpReq)
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

	if syncResp.Message != "" && strings.Contains(syncResp.Message, "UPGRADE_REQUIRED") {
		fmt.Fprintf(os.Stderr, "\n==================================================\n  [UPGRADE REQUIRED] %s\n==================================================\n\n", syncResp.Message)
	}

	// First contact with a signing control plane: pin its public key (trust on first use over
	// the already-trusted control plane channel). Afterwards only that key is honored.
	pinnedNow := false
	if syncResp.Bundle != nil && syncResp.Bundle.SigAlg == "ed25519" && !s.Managed() {
		if pubErr := s.pinFromServer(client, serverURL, syncResp.Bundle.KeyID, syncResp.Bundle.AssetID); pubErr != nil {
			return Bundle{}, false, fmt.Errorf("could not pin control plane policy key: %w", pubErr)
		}
		pinnedNow = true
	}
	// A machine must never be left "managed" (pinned) without signed rules to go with the pin: if the
	// first bundle we pinned for cannot be accepted, undo the pin so the machine stays as it was
	// instead of failing closed on its previous, unsigned cache.
	undoFreshPin := func() {
		if pinnedNow {
			_ = os.Remove(s.pinPath())
		}
	}

	if syncResp.Directive == "KILL_SWITCH" || (syncResp.Bundle != nil && syncResp.Bundle.KillSwitch) {
		// Persist kill-switch so it remains locked even offline. On a managed machine the
		// signed bundle is stored as-is; an unsigned/forged kill directive still blocks this
		// run but is not persisted.
		if syncResp.Bundle != nil && syncResp.Bundle.PolicyCedar != "" {
			kb := *syncResp.Bundle
			if !s.Managed() {
				kb.KillSwitch = true // legacy/unsigned: the directive itself is the instruction
			}
			if kb.KillSwitch {
				if err := s.Accept(kb); err == nil {
					return Bundle{}, false, ErrKillSwitchActive
				}
				undoFreshPin()
			}
		}
		if !s.Managed() {
			_ = s.Accept(Bundle{
				Version:    state.Version,
				Digest:     state.Digest,
				KillSwitch: true,
			})
		}
		return Bundle{}, false, ErrKillSwitchActive
	}

	if syncResp.Directive == "UPDATE_REQUIRED" && syncResp.Bundle != nil {
		// An enrolled machine that syncs WITHOUT its credential (credentials saved elsewhere, a
		// plain `bapedge sync` from another shell) is answered as an anonymous caller: the fleet
		// bundle, issued for no asset. That is not tampering, it is simply not this machine's bundle.
		// Keep the verified cached rules, exactly as when the control plane is unreachable.
		if s.Managed() && s.credential() == "" && syncResp.Bundle.AssetID != s.AssetID() {
			cedarPath, schemaPath, cur, err := s.Current()
			if err != nil {
				return Bundle{}, true, err
			}
			cedarData, _ := os.ReadFile(cedarPath)
			schemaData, _ := os.ReadFile(schemaPath)
			fmt.Fprintln(os.Stderr, "[BAP] policy sync was anonymous (no enrollment credential found); keeping the verified cached rules. Run `bap login` or pass the credentials this machine enrolled with.")
			return Bundle{Version: cur.Version, Digest: cur.Digest, PolicyCedar: string(cedarData), SchemaJSON: string(schemaData), KillSwitch: cur.KillSwitch}, true, nil
		}
		if err := s.Accept(*syncResp.Bundle); err != nil {
			undoFreshPin()
			return Bundle{}, false, err
		}
		s.adoptServerURL(serverURL)
		return *syncResp.Bundle, false, nil
	}

	// CURRENT: read current cached
	cedarPath, schemaPath, currentState, err := s.Current()
	if err != nil {
		return Bundle{}, false, err
	}
	s.touchLastSync() // freshness marker for RefreshIfStale; not part of the signed fields
	s.adoptServerURL(serverURL)
	cedarData, _ := os.ReadFile(cedarPath)
	schemaData, _ := os.ReadFile(schemaPath)
	return Bundle{
		Version:     currentState.Version,
		Digest:      currentState.Digest,
		PolicyCedar: string(cedarData),
		SchemaJSON:  string(schemaData),
	}, false, nil
}
