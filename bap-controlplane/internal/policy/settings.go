package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FleetAssetID is the pseudo asset used to address the fleet-wide default.
const FleetAssetID = "*"

// AssetOverride is a per-machine override of fleet enforcement settings. Overrides are keyed
// by the machine's asset id (hardware-derived), not by registered agent, so re-registering a
// client does not shed or change them.
type AssetOverride struct {
	ZSPReadExempt *bool  `json:"zsp_read_exempt,omitempty"`
	UpdatedAt     string `json:"updated_at"`
	UpdatedBy     string `json:"updated_by,omitempty"`
}

// SettingsSnapshot is the admin-facing view of all enforcement settings.
type SettingsSnapshot struct {
	Version         uint64                   `json:"version"`
	FleetReadExempt bool                     `json:"fleet_zsp_read_exempt"`
	AssetOverrides  map[string]AssetOverride `json:"asset_overrides"`
	EnrolledAssets  map[string]string        `json:"enrolled_assets"` // instance id -> asset id (find ids for overrides here)
}

type persistedSettings struct {
	Version         uint64                   `json:"version"`
	FleetReadExempt bool                     `json:"fleet_zsp_read_exempt"`
	AssetOverrides  map[string]AssetOverride `json:"asset_overrides"`
	EnrolledAssets  map[string]string        `json:"enrolled_assets,omitempty"`
}

// EnrolledAssetFor derives the asset id for an enrolled workstation: the hardware id it
// reported at enrollment, or a stable id derived from its instance id when it reported none.
func EnrolledAssetFor(instanceID, reportedAssetID string) string {
	if a := strings.TrimSpace(reportedAssetID); a != "" && len(a) <= 128 {
		return a
	}
	return "inst:" + strings.TrimSpace(instanceID)
}

// BindEnrolledAsset records the asset id of an authenticated enrollment (OTC register or OIDC
// login). Authenticated re-enrollment may rebind; unauthenticated callers can never reach it.
func (s *Store) BindEnrolledAsset(instanceID, reportedAssetID string) string {
	asset := EnrolledAssetFor(instanceID, reportedAssetID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enrolledAssets == nil {
		s.enrolledAssets = map[string]string{}
	}
	// An older client re-enrolling reports no hardware id. That must never downgrade a machine's
	// existing binding to an id derived from its instance name (the pinned client would then
	// reject every bundle it is sent).
	if strings.TrimSpace(reportedAssetID) == "" {
		if cur, ok := s.enrolledAssets[instanceID]; ok && cur != "" {
			return cur
		}
	}
	if s.enrolledAssets[instanceID] != asset {
		s.enrolledAssets[instanceID] = asset
		_ = s.saveSettingsLocked()
	}
	return asset
}

// EnrolledAsset returns the asset bound to an enrolled workstation instance.
func (s *Store) EnrolledAsset(instanceID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.enrolledAssets[instanceID]
	return a, ok
}

// RotateSigner swaps in a rotated signer (the old key signed the link).
func (s *Store) RotateSigner(next *Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signer = next
	s.bumpLocked() // new signatures must be fetched by every client
	_ = s.saveSettingsLocked()
}

// EnablePersistence stores settings in path and restores them now. The version counter is
// restored too (and advanced by one) so a restart never moves it backwards: clients refuse
// rollbacks, so a reset counter would strand them on stale rules.
func (s *Store) EnablePersistence(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settingsPath = path
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// First start: nothing to restore. Failing to write the initial file is not fatal (the
		// settings simply stay in memory until a later write succeeds); only an unreadable or
		// corrupt EXISTING file refuses to start, because enforcement settings would be unknown.
		_ = s.saveSettingsLocked()
		return nil
	}
	if err != nil {
		return err
	}
	var ps persistedSettings
	if err := json.Unmarshal(data, &ps); err != nil {
		return fmt.Errorf("corrupt policy settings %s: %w", path, err)
	}
	s.bundle.ZSPReadExempt = ps.FleetReadExempt
	if ps.AssetOverrides != nil {
		s.assetOverrides = ps.AssetOverrides
	}
	if ps.EnrolledAssets != nil {
		s.enrolledAssets = ps.EnrolledAssets
	}
	if ps.Version >= s.bundle.Version {
		s.bundle.Version = ps.Version + 1
	}
	s.bundle.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return s.saveSettingsLocked()
}

func (s *Store) saveSettingsLocked() error {
	if s.settingsPath == "" {
		return nil
	}
	ps := persistedSettings{Version: s.bundle.Version, FleetReadExempt: s.bundle.ZSPReadExempt, AssetOverrides: s.assetOverrides, EnrolledAssets: s.enrolledAssets}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.settingsPath), 0700); err != nil {
		return err
	}
	// A unique temp file per write: two control planes pointed at one directory (tests, a
	// misconfigured second instance) must never collide on a shared ".tmp" name.
	tmpFile, err := os.CreateTemp(filepath.Dir(s.settingsPath), "policy-settings-*.tmp")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Windows refuses to replace a file that another writer/reader has open for a moment; the
	// replacement succeeds as soon as they let go, so retry briefly before giving up.
	var renameErr error
	for attempt := 0; attempt < 40; attempt++ {
		if renameErr = os.Rename(tmp, s.settingsPath); renameErr == nil {
			return nil
		}
		time.Sleep(time.Duration(5+attempt) * time.Millisecond)
	}
	_ = os.Remove(tmp)
	return renameErr
}

func (s *Store) bumpLocked() {
	s.bundle.Version++
	s.bundle.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	s.bundle.Signature = SignBundle(s.bundle.Version, s.bundle.Digest, s.bundle.KillSwitch, s.signingKey)
}

// SetReadExempt sets the ZSP read-exemption for the fleet (assetID "" or "*") or one asset.
// Every change advances the single global version so clients see it on their next sync.
func (s *Store) SetReadExempt(assetID string, exempt bool, by string) (Bundle, error) {
	assetID = strings.TrimSpace(assetID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if assetID == "" || assetID == FleetAssetID {
		s.bundle.ZSPReadExempt = exempt
	} else {
		if s.assetOverrides == nil {
			s.assetOverrides = map[string]AssetOverride{}
		}
		v := exempt
		s.assetOverrides[assetID] = AssetOverride{ZSPReadExempt: &v, UpdatedAt: time.Now().UTC().Format(time.RFC3339), UpdatedBy: by}
	}
	s.bumpLocked()
	return s.bundle, s.saveSettingsLocked()
}

// ClearAssetOverride removes a machine's override so it follows the fleet default again.
func (s *Store) ClearAssetOverride(assetID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.assetOverrides[assetID]; !ok {
		return false, nil
	}
	delete(s.assetOverrides, assetID)
	s.bumpLocked()
	return true, s.saveSettingsLocked()
}

// Settings returns a copy of the current settings for the admin API.
func (s *Store) Settings() SettingsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := SettingsSnapshot{Version: s.bundle.Version, FleetReadExempt: s.bundle.ZSPReadExempt, AssetOverrides: map[string]AssetOverride{}, EnrolledAssets: map[string]string{}}
	for inst, a := range s.enrolledAssets {
		out.EnrolledAssets[inst] = a
	}
	ids := make([]string, 0, len(s.assetOverrides))
	for id := range s.assetOverrides {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out.AssetOverrides[id] = s.assetOverrides[id]
	}
	return out
}

// applyAssetOverride returns b with the asset's overrides applied. Caller holds s.mu.
func (s *Store) applyAssetOverride(b Bundle, assetID string) Bundle {
	if ov, ok := s.assetOverrides[assetID]; ok && assetID != "" && ov.ZSPReadExempt != nil {
		b.ZSPReadExempt = *ov.ZSPReadExempt
	}
	return b
}
