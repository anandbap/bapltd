package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type remoteRevocations struct {
	KillSwitch         bool     `json:"kill_switch"`
	RevokedSessions    []string `json:"revoked_sessions"`
	DeregisteredAgents []string `json:"deregistered_agents"`
	QuarantinedAgents  []string `json:"quarantined_agents"`
	RevokedAgents      []string `json:"revoked_agents"`
	RecoveryProtocol   int      `json:"recovery_protocol"`
	RestoredSessions   []string `json:"restored_sessions"`
	RestoredAgents     []string `json:"restored_agents"`
	FleetRestored      bool     `json:"fleet_restore_confirmed"`
}

func hasTarget(ids, targets []string) bool {
	for _, id := range ids {
		for _, target := range targets {
			if target != "" && strings.EqualFold(id, target) {
				return true
			}
		}
	}
	return false
}

func mergeRevocationCache(existing map[string]any, data remoteRevocations, targets []string) map[string]any {
	if existing == nil {
		existing = make(map[string]any)
	}
	frozen := hasTarget(data.QuarantinedAgents, targets)
	if data.RecoveryProtocol >= 1 {
		oldKill, _ := existing["kill_switch"].(bool)
		oldFrozen, _ := existing["frozen"].(bool)
		data.KillSwitch = data.KillSwitch || (oldKill && !data.FleetRestored)
		frozen = frozen || (oldFrozen && !hasTarget(data.RestoredAgents, targets))
		var previous []string
		if raw, err := json.Marshal(existing["revoked_sessions"]); err == nil {
			_ = json.Unmarshal(raw, &previous)
		}
		for _, id := range previous {
			if !hasTarget(data.RevokedSessions, []string{id}) && !hasTarget(data.RestoredSessions, []string{id}) {
				data.RevokedSessions = append(data.RevokedSessions, id)
			}
		}
	}
	existing["kill_switch"], existing["frozen"], existing["revoked_sessions"] = data.KillSwitch, frozen, data.RevokedSessions
	existing["last_sync"] = time.Now().UTC()
	return existing
}

var revocationCacheMu sync.Mutex

func writeRevocationCache(path string, data remoteRevocations, targets []string) error {
	revocationCacheMu.Lock()
	defer revocationCacheMu.Unlock()
	var existing map[string]any
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &existing)
	}
	raw, err := json.MarshalIndent(mergeRevocationCache(existing, data, targets), "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "policy-state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
