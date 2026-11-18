package api

import (
	"strings"
	"time"

	"bap-controlplane/pkg/types"
)

// Dashboard labels for ZSP grants (BAP-1102). The recorded grant is the source of truth: how it was
// obtained (delegation type), what class of ceiling applied, and how many uses it carries and has left.

// grantMode maps a recorded delegation type to how the grant was approved.
//
//	AUTOMATIC     policy allowed it without a human (single command batch or an allow-tier request)
//	AUTO_APPROVED a human enabled bounded step-up auto-approve (BAP-1100)
//	DEV_OVERRIDE  a human opened a developer override window
//	MANUAL        a human approved it out of band (step-up / HITL)
func grantMode(delegationType string) string {
	d := strings.ToLower(strings.TrimSpace(delegationType))
	switch {
	case d == "auto_approve":
		return "AUTO_APPROVED"
	case d == "dev_override":
		return "DEV_OVERRIDE"
	case d == "manual_hitl", strings.Contains(d, "oob"), strings.Contains(d, "step_up"):
		return "MANUAL"
	default:
		return "AUTOMATIC"
	}
}

// grantStatus reports ACTIVE while uses and lifetime remain, EXPIRED when the lifetime ended
// unused, otherwise USED (burned).
func grantStatus(g *types.TaskGrant, now time.Time) string {
	if !g.IsBurned && g.RemainingUses > 0 && now.Before(g.ExpiresAt) {
		return "ACTIVE"
	}
	if now.After(g.ExpiresAt) && !g.IsBurned && g.RemainingUses > 0 {
		return "EXPIRED"
	}
	return "USED"
}

// grantUses returns how many uses a grant carries and how many were consumed.
func grantUses(g *types.TaskGrant) (max, consumed int) {
	max = g.MaxUses
	if max <= 0 {
		max = 1
	}
	consumed = max - g.RemainingUses
	if consumed < 0 {
		consumed = 0
	}
	return max, consumed
}

// grantClassLabel falls back to a label derived from the use count for grants recorded before
// classes existed.
func grantClassLabel(g *types.TaskGrant) string {
	if g.GrantClass != "" {
		return g.GrantClass
	}
	if g.MaxUses > 1 {
		return "multi_use"
	}
	return "single_use"
}
