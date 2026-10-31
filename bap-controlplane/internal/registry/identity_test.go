package registry

import (
	"bap-controlplane/pkg/types"
	"testing"
)

func TestIdentityDoesNotMergeMachinesByEmailOrHostname(t *testing.T) {
	s := NewStore("bap.internal")
	one := s.EnsureSessionAgent("bapedge", "one", "", "same@example.test", "same-host")
	two := s.EnsureSessionAgent("bapedge", "two", "", "same@example.test", "same-host")
	if one.AgentID == two.AgentID || len(s.List()) != 2 {
		t.Fatal("different identities collapsed into one machine")
	}
}

func TestHeartbeatNeverClearsAdministrativeFreeze(t *testing.T) {
	s := NewStore("bap.internal")
	agent := s.EnsureSessionAgent("bapedge", "machine", "", "", "host")
	_, _ = s.QuarantineTarget(agent.AgentID, "test freeze")
	if err := s.HeartbeatInstance("claude-code", "machine"); err == nil {
		t.Fatal("heartbeat accepted frozen workstation")
	}
	if !s.WorkstationBlocked("machine", "bapedge", true) || agent.Status != types.StatusQuarantined {
		t.Fatal("heartbeat cleared freeze")
	}
	_, _ = s.UnquarantineTarget(agent.AgentID)
	if s.WorkstationBlocked("machine", "bapedge", true) {
		t.Fatal("explicit restore did not update identity index")
	}
	if err := s.HeartbeatInstance("claude-code", "machine"); err != nil {
		t.Fatal(err)
	}
}
