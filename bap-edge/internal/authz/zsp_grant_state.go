package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"bap-edge/pkg/types"
)

// A task grant is replicated into the directory of every session it is linked to. These helpers
// keep that replication from turning a single-use grant into a multi-use one (BAP-1097):
//
//   - freshestGrantState merges every replica so the most consumed state always wins.
//   - persistGrantEverywhere writes the updated state to every replica and, once the grant is
//     burned, writes a workstation-wide tombstone that no replica can contradict.
//   - callers hold the workstation-wide "grantspend-<id>" lock around read-modify-write.

func burnedTombstonePath(zspDir, grantID string) string {
	return filepath.Join(zspDir, "burned", sanitizeZSPKey(grantID)+".json")
}

type burnTombstone struct {
	GrantID  string    `json:"grant_id"`
	Reason   string    `json:"reason"`
	BurnedAt time.Time `json:"burned_at"`
}

func writeBurnTombstone(zspDir, grantID, reason string) error {
	if reason == "" {
		reason = "burned"
	}
	data, err := json.Marshal(burnTombstone{GrantID: grantID, Reason: reason, BurnedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	return writeFileAtomic(burnedTombstonePath(zspDir, grantID), data, 0600)
}

func readBurnTombstone(zspDir, grantID string) (*burnTombstone, bool) {
	data, err := os.ReadFile(burnedTombstonePath(zspDir, grantID))
	if err != nil {
		return nil, false
	}
	var t burnTombstone
	if json.Unmarshal(data, &t) != nil {
		// An unreadable tombstone still means "burned": fail closed.
		return &burnTombstone{GrantID: grantID, Reason: "burned (unreadable tombstone)"}, true
	}
	return &t, true
}

// freshestGrantState returns a copy of g carrying the most consumed state found in any replica
// or tombstone. Replicas whose immutable authority signature differs from g's are ignored, so a
// substituted file cannot mask the real state.
func freshestGrantState(zspDir, sessionID string, g *types.TaskGrant) *types.TaskGrant {
	if g == nil {
		return nil
	}
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	merged := *g
	for _, dir := range allLinkedDirs(sessionID, g) {
		data, err := os.ReadFile(filepath.Join(grantsDirForSession(zspDir, dir), sanitizeZSPKey(g.GrantID)+".json"))
		if err != nil {
			continue
		}
		var replica types.TaskGrant
		if json.Unmarshal(data, &replica) != nil || replica.GrantID != g.GrantID || replica.AuthoritySignature != g.AuthoritySignature {
			continue
		}
		if replica.IsBurned && !merged.IsBurned {
			merged.IsBurned = true
			merged.BurnReason = replica.BurnReason
		}
		if replica.RemainingUses < merged.RemainingUses {
			merged.RemainingUses = replica.RemainingUses
			merged.ConsumedCmd = replica.ConsumedCmd
			merged.ReceiptID = replica.ReceiptID
		}
	}
	if t, ok := readBurnTombstone(zspDir, g.GrantID); ok {
		merged.IsBurned = true
		merged.RemainingUses = 0
		if merged.BurnReason == "" {
			merged.BurnReason = t.Reason
		}
	}
	return &merged
}

// persistGrantEverywhere writes the grant state to the owning session first (an error there is
// returned so the caller can fail closed), then to every linked replica, then writes the burn
// tombstone for a burned grant.
func persistGrantEverywhere(zspDir, sessionID string, g *types.TaskGrant) error {
	if g == nil {
		return nil
	}
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	owner := g.SessionID
	if owner == "" {
		owner = sessionID
	}
	if err := saveSessionGrant(zspDir, owner, g); err != nil {
		return fmt.Errorf("owner replica: %w", err)
	}
	var firstErr error
	for _, dir := range allLinkedDirs(sessionID, g) {
		if dir == "" || dir == owner {
			continue
		}
		if err := saveSessionGrant(zspDir, dir, g); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("replica %s: %w", dir, err)
		}
	}
	if g.IsBurned || g.RemainingUses <= 0 {
		if err := writeBurnTombstone(zspDir, g.GrantID, g.BurnReason); err != nil {
			return fmt.Errorf("burn tombstone: %w", err)
		}
	}
	// A failed replica write is covered by the tombstone for burned grants; for a live grant with
	// remaining uses the owner copy is authoritative, so only report the owner failure.
	_ = firstErr
	return nil
}
