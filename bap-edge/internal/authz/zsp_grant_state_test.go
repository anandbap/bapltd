package authz

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// BAP-1097: a grant linked into several sessions is replicated into each session directory.
// These tests pin the single-use / revocation guarantees across those replicas.

func mintLinkedGrant(t *testing.T, zspDir, owner, linked string, uses int) string {
	t.Helper()
	grant, _, err := SubmitTaskEnvelopeWithDelegation(
		zspDir, owner, "claude-code",
		"CODE_INSPECTION", "inspect repository", "inspect repository",
		[]string{"git:status"}, []string{"workspace://current"},
		"", "human_interactive_prompt", uses, 0,
		owner, linked,
	)
	if err != nil || grant == nil {
		t.Fatalf("mint linked grant failed: %v", err)
	}
	return grant.GrantID
}

func TestLinkedSessionsCannotDoubleSpendSingleUseGrant(t *testing.T) {
	ws := t.TempDir()
	checks := ResolveZSPCommandChecks("git status -sb", "git", "status -sb", "", "", ws)

	for round := 0; round < 15; round++ {
		zspDir := t.TempDir()
		a, b := "sess-link-a", "sess-link-b"
		mintLinkedGrant(t, zspDir, a, b, 1)

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, sid := range []string{a, b} {
			wg.Add(1)
			go func(sid string) {
				defer wg.Done()
				<-start
				_, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, sid, "claude-code", checks, "git status -sb", ws, true, nil)
				results <- err
			}(sid)
		}
		close(start)
		wg.Wait()
		close(results)

		successes := 0
		for err := range results {
			if err == nil {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("round %d: single-use grant linked to two sessions was spent %d times, want exactly 1", round, successes)
		}
	}
}

func TestSequentialLinkedSessionSpendSeesBurn(t *testing.T) {
	ws := t.TempDir()
	zspDir := t.TempDir()
	a, b := "sess-seq-a", "sess-seq-b"
	mintLinkedGrant(t, zspDir, a, b, 1)
	checks := ResolveZSPCommandChecks("git status", "git", "status", "", "", ws)

	if _, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, a, "claude-code", checks, "git status", ws, true, nil); err != nil {
		t.Fatalf("first spend should succeed: %v", err)
	}
	if _, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, b, "claude-code", checks, "git status", ws, true, nil); err == nil {
		t.Fatal("linked session spent a grant already burned by its sibling")
	}
}

func TestRevokingGrantBurnsLinkedReplicas(t *testing.T) {
	ws := t.TempDir()
	zspDir := t.TempDir()
	a, b := "sess-rev-a", "sess-rev-b"
	mintLinkedGrant(t, zspDir, a, b, 3)
	checks := ResolveZSPCommandChecks("git status", "git", "status", "", "", ws)

	n, err := RevokeSessionZSPGrants(zspDir, a, "")
	if err != nil || n != 1 {
		t.Fatalf("revoke = (%d, %v), want (1, nil)", n, err)
	}
	if _, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, b, "claude-code", checks, "git status", ws, true, nil); err == nil {
		t.Fatal("linked session still spent a grant the operator revoked")
	}
}

func TestBurnTombstoneDefeatsRestoredReplica(t *testing.T) {
	ws := t.TempDir()
	zspDir := t.TempDir()
	a, b := "sess-tomb-a", "sess-tomb-b"
	id := mintLinkedGrant(t, zspDir, a, b, 1)
	checks := ResolveZSPCommandChecks("git status", "git", "status", "", "", ws)

	// Snapshot the live replicas before the grant is spent.
	snapshots := map[string][]byte{}
	for _, sid := range []string{a, b} {
		p := filepath.Join(grantsDirForSession(zspDir, sid), sanitizeZSPKey(id)+".json")
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("replica for %s missing: %v", sid, err)
		}
		snapshots[p] = data
	}

	if _, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, a, "claude-code", checks, "git status", ws, true, nil); err != nil {
		t.Fatalf("first spend should succeed: %v", err)
	}
	if _, err := os.Stat(burnedTombstonePath(zspDir, id)); err != nil {
		t.Fatalf("burned grant left no tombstone: %v", err)
	}

	// Replay: restore the original un-burned replica files.
	for p, data := range snapshots {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatalf("restore replica: %v", err)
		}
	}
	for _, sid := range []string{a, b} {
		if _, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, sid, "claude-code", checks, "git status", ws, true, nil); err == nil {
			t.Fatalf("session %s revived a burned grant by restoring an old replica", sid)
		}
	}
}

func TestFreshestGrantStateIgnoresSubstitutedReplica(t *testing.T) {
	zspDir := t.TempDir()
	a, b := "sess-sub-a", "sess-sub-b"
	id := mintLinkedGrant(t, zspDir, a, b, 2)

	// A replica with a different authority signature must not be trusted to lower the count.
	grants, err := loadSessionGrants(zspDir, a, nil)
	if err != nil || len(grants) != 1 {
		t.Fatalf("load grants: %v (%d)", err, len(grants))
	}
	forged := *grants[0]
	forged.AuthoritySignature = "forged"
	forged.RemainingUses = 0
	forged.IsBurned = true
	if err := saveSessionGrant(zspDir, b, &forged); err != nil {
		t.Fatalf("write forged replica: %v", err)
	}
	merged := freshestGrantState(zspDir, a, grants[0])
	if merged.IsBurned || merged.RemainingUses != 2 {
		t.Fatalf("forged replica altered state of %s: burned=%v remaining=%d", id, merged.IsBurned, merged.RemainingUses)
	}
}
