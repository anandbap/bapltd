package authz

import (
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

func TestNewWorkstationLoginSupersedesOnlyPriorLogin(t *testing.T) {
	m := NewTokenMinter("synthetic-test-signing-key", time.Minute)
	agent := &types.RegisteredAgent{AgentID: "alice-laptop", AppID: "workstation-laptop", InstanceID: "laptop", PermittedScopes: []string{"cli:exec"}}
	first, _, err := m.MintWorkstationSession(agent, "release-one")
	if err != nil {
		t.Fatal(err)
	}
	other := *agent
	other.AgentID, other.InstanceID = "alice-desktop", "desktop"
	unrelated, _, err := m.MintWorkstationSession(&other, "release-one")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := m.MintWorkstationSession(agent, "release-two")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(first); err == nil {
		t.Fatal("superseded workstation login remains valid")
	}
	if _, err := m.Verify(second); err != nil {
		t.Fatal("new login rejected:", err)
	}
	if _, err := m.Verify(unrelated); err != nil {
		t.Fatal("login revoked another workstation:", err)
	}
	agent.RecoveryOnly = true
	if _, _, err := m.MintWorkstationSession(agent, "release-three"); err == nil {
		t.Fatal("reporting-only identity received a login token")
	}
	if _, err := m.Verify(second); err != nil {
		t.Fatal("failed login invalidated the current credential:", err)
	}
}
