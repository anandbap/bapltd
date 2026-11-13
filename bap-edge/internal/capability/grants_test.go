package capability

import (
	"path/filepath"
	"testing"
	"time"

	"bap-edge/pkg/types"
)

func TestTaskGrantConversionNeverWidensReadScope(t *testing.T) {
	now := time.Now().UTC()
	ws := t.TempDir()
	grant := types.TaskGrant{GrantID: "g", SessionID: "s", RemainingUses: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), AllowedActions: []string{"fs:read"}, AllowedResources: []string{"workspace://current"}, RequestedActions: []string{"fs:write"}}
	set, err := FromTaskGrant(grant, ws, now)
	if err != nil || len(set.Filesystem) != 1 || set.Filesystem[0].Mode != "read" || set.Filesystem[0].Path != ws || !set.ExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatalf("conversion: %+v %v", set, err)
	}
	for _, mutate := range []func(*types.TaskGrant){
		func(g *types.TaskGrant) { g.IsBurned = true }, func(g *types.TaskGrant) { g.ExpiresAt = now }, func(g *types.TaskGrant) { g.RemainingUses = 0 },
		func(g *types.TaskGrant) { g.AllowedActions = []string{"cli:python:exec"} }, func(g *types.TaskGrant) { g.AllowedResources = []string{"file://" + filepath.Join(ws, ".env")} },
		func(g *types.TaskGrant) { g.AllowedResources = []string{"file://relative"} }, func(g *types.TaskGrant) { g.AllowedResources = []string{"system://local"} },
	} {
		g := grant
		mutate(&g)
		if _, err := FromTaskGrant(g, ws, now); err == nil {
			t.Fatalf("unsafe grant converted: %+v", g)
		}
	}
}

func TestTaskGrantNetworkConversion(t *testing.T) {
	now := time.Now().UTC()
	g := types.TaskGrant{GrantID: "g", SessionID: "s", RemainingUses: 1, ExpiresAt: now.Add(time.Hour), AllowedActions: []string{"net:connect"}, AllowedResources: []string{"https://registry.example"}}
	set, err := FromTaskGrant(g, t.TempDir(), now)
	if err != nil || len(set.Network) != 1 || set.Network[0].Host != "registry.example" || set.Network[0].Port != "443" {
		t.Fatalf("network: %+v %v", set, err)
	}
	for _, resource := range []string{"https://169.254.169.254", "https://metadata.google.internal", "https://*.example", "https://registry.example/private", "https://user:password@registry.example"} {
		g.AllowedResources = []string{resource}
		if _, err := FromTaskGrant(g, t.TempDir(), now); err == nil {
			t.Fatalf("unsafe destination accepted: %s", resource)
		}
	}
}
