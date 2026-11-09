package registry

import (
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

func TestOTCEnrolledAgentPersistsAcrossSessionEndAndPurge(t *testing.T) {
	s := NewStore("bap.internal")

	// Pre-register an agent with an ephemeral app name, e.g. "claude-code"
	preReq := types.PreRegisterRequest{
		AppID:      "claude-code",
		OwnerEmail: "developer@internal.local",
		AgentName:  "Developer Laptop",
	}
	preReg, err := s.PreRegister(preReq)
	if err != nil {
		t.Fatalf("PreRegister failed: %v", err)
	}

	// Enroll via OTC (EnrollWithVersion)
	enrolled, err := s.EnrollWithVersion(preReg.AgentID, "test-binary-hash", "test-pub-key", "DESKTOP-DEV", "windows", "amd64", "inst-dev-1", "1.12.11", 1)
	if err != nil {
		t.Fatalf("EnrollWithVersion failed: %v", err)
	}

	if enrolled.AuthMode != "otc" {
		t.Errorf("Expected AuthMode 'otc', got %q", enrolled.AuthMode)
	}
	if enrolled.Status != types.StatusActive {
		t.Errorf("Expected StatusActive, got %q", enrolled.Status)
	}
	if enrolled.EnrolledAt == nil {
		t.Errorf("Expected EnrolledAt to be set, got nil")
	}

	// 1. Simulate an ephemeral Claude Code session terminating
	s.EndSessionAgent("claude-code", enrolled.InstanceID)

	agentAfterEnd, err := s.Get(enrolled.AgentID)
	if err != nil {
		t.Fatalf("Get failed after EndSessionAgent: %v", err)
	}
	if agentAfterEnd.Status == types.StatusDeregistered {
		t.Fatalf("BUG: Enrolled workstation agent was deregistered by EndSessionAgent!")
	}
	if agentAfterEnd.Status != types.StatusActive {
		t.Errorf("Expected StatusActive after EndSessionAgent, got %q", agentAfterEnd.Status)
	}

	// 2. Simulate PurgeStale after long idle period
	purged := s.PurgeStale(1 * time.Nanosecond)
	if purged != 0 {
		t.Errorf("Expected 0 purged workstation agents, got %d", purged)
	}

	agentAfterPurge, err := s.Get(enrolled.AgentID)
	if err != nil {
		t.Fatalf("Get failed after PurgeStale: %v", err)
	}
	if agentAfterPurge.Status != types.StatusActive {
		t.Errorf("Expected StatusActive after PurgeStale, got %q", agentAfterPurge.Status)
	}

	// 3. Explicit Deregister SHOULD deregister the agent
	_, err = s.Deregister(enrolled.AgentID)
	if err != nil {
		t.Fatalf("Deregister failed: %v", err)
	}
	agentAfterDereg, err := s.Get(enrolled.AgentID)
	if err != nil {
		t.Fatalf("Get failed after explicit Deregister: %v", err)
	}
	if agentAfterDereg.Status != types.StatusDeregistered {
		t.Errorf("Expected StatusDeregistered after explicit Deregister, got %q", agentAfterDereg.Status)
	}
}
