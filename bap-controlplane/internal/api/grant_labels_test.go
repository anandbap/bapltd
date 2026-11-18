package api

import (
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

// BAP-1102: the dashboard must label how a grant was approved and how many uses it has.

func TestGrantModeLabels(t *testing.T) {
	cases := map[string]string{
		"policy_automatic_batch":   "AUTOMATIC",
		"human_interactive_prompt": "AUTOMATIC",
		"auto_approve":             "AUTO_APPROVED",
		"dev_override":             "DEV_OVERRIDE",
		"human_interactive_oob":    "MANUAL",
		"step_up_approval":         "MANUAL",
		"manual_hitl":              "MANUAL",
		"":                         "AUTOMATIC",
	}
	for in, want := range cases {
		if got := grantMode(in); got != want {
			t.Fatalf("grantMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGrantUsesAndStatusForMultiUseGrant(t *testing.T) {
	now := time.Now()
	g := &types.TaskGrant{MaxUses: 25, RemainingUses: 18, ExpiresAt: now.Add(5 * time.Minute)}
	if max, used := grantUses(g); max != 25 || used != 7 {
		t.Fatalf("uses = (%d, %d), want (25, 7)", max, used)
	}
	if grantStatus(g, now) != "ACTIVE" {
		t.Fatal("a partly used multi-use grant is still ACTIVE, not burned")
	}
	g.RemainingUses, g.IsBurned = 0, true
	if grantStatus(g, now) != "USED" {
		t.Fatal("a fully consumed grant is USED")
	}
	expired := &types.TaskGrant{MaxUses: 5, RemainingUses: 5, ExpiresAt: now.Add(-time.Minute)}
	if grantStatus(expired, now) != "EXPIRED" {
		t.Fatal("an unused grant past its lifetime is EXPIRED")
	}
}

func TestGrantClassLabelFallsBackForLegacyGrants(t *testing.T) {
	if got := grantClassLabel(&types.TaskGrant{MaxUses: 1}); got != "single_use" {
		t.Fatalf("legacy 1-use grant = %q", got)
	}
	if got := grantClassLabel(&types.TaskGrant{MaxUses: 40}); got != "multi_use" {
		t.Fatalf("legacy 40-use grant = %q", got)
	}
	if got := grantClassLabel(&types.TaskGrant{MaxUses: 25, GrantClass: "workspace_edit"}); got != "workspace_edit" {
		t.Fatalf("recorded class lost: %q", got)
	}
}

func TestStoredGrantKeepsItsClass(t *testing.T) {
	s := setupTestServer()
	g := &types.TaskGrant{
		GrantID: "grant-class-1", EnvelopeID: "env-1", SessionID: "sess-1", PrincipalSVID: "spiffe://x", HumanOwner: "u@x",
		AllowedActions: []string{"fs:file:write"}, AllowedResources: []string{"workspace://current"},
		MaxUses: 25, RemainingUses: 20, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute),
		DelegationType: "auto_approve", GrantClass: "workspace_edit",
	}
	if err := s.sessionStore.SaveZSPGrant(g); err != nil {
		t.Fatal(err)
	}
	got, err := s.sessionStore.GetZSPGrant("grant-class-1")
	if err != nil || got.GrantClass != "workspace_edit" || got.DelegationType != "auto_approve" {
		t.Fatalf("stored grant = %+v, %v", got, err)
	}
}
