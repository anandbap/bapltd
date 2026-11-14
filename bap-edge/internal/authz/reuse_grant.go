package authz

import (
	"time"

	"bap-edge/pkg/types"
)

// FindLiveApprovedGrant returns a grant that a human already approved for this session when it is
// still usable and already covers every requested action and resource.
//
// It exists so that retrying `zsp authorize` after `zsp approve` does not raise a brand-new request.
// It never mints or widens anything:
//   - the grant must exist on disk and pass the PEP HMAC signature check (forged files are skipped),
//   - it must be unexpired, unburned and have uses left,
//   - a human-decided request in the "approved" state must name that exact grant for this session,
//   - every requested action and resource must already be allowed by that grant (exact match).
func FindLiveApprovedGrant(zspDir, sessionID, clientType string, actions, resources []string, now time.Time) (*types.TaskGrant, *PendingApproval) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	if len(actions) == 0 {
		return nil, nil
	}
	if len(resources) == 0 {
		resources = []string{"workspace://current"}
	}
	_, _, minter, pepSecret, err := EnsureSessionPrincipal(zspDir, sessionID, clientType)
	if err != nil {
		return nil, nil
	}
	engine := NewZSPEngine(minter, pepSecret)
	grants, err := loadSessionGrants(zspDir, sessionID, engine) // verifies signatures
	if err != nil || len(grants) == 0 {
		return nil, nil
	}
	approvals, err := ListPendingApprovals(zspDir)
	if err != nil {
		return nil, nil
	}
	byID := make(map[string]*types.TaskGrant, len(grants))
	for _, g := range grants {
		byID[g.GrantID] = g
	}
	for i := range approvals {
		a := approvals[i]
		if a.Status != "approved" || a.SessionID != sessionID || a.GrantID == "" {
			continue
		}
		g := byID[a.GrantID]
		if g == nil || g.IsBurned || g.RemainingUses <= 0 || !now.Before(g.ExpiresAt) {
			continue
		}
		if coversAll(g.AllowedActions, actions) && coversAll(g.AllowedResources, resources) {
			return g, &a
		}
	}
	return nil, nil
}

func coversAll(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, h := range have {
		set[h] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}
