package authz

import (
	"bap-controlplane/pkg/types"
	"testing"
	"time"
)

func TestEnrollmentSurvivesRestartButExecutionAuthorityDoesNot(t *testing.T) {
	before, after := NewTokenMinter("test-stable-signing-key", time.Minute), NewTokenMinter("test-stable-signing-key", time.Minute)
	agent := &types.RegisteredAgent{AgentID: "station", AppID: "bapedge", InstanceID: "machine", PermittedScopes: []string{"cli:exec"}}
	identity, _, err := before.MintWorkstationSession(agent, "binary")
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := after.Verify(identity); err != nil || !IsWorkstationCredential(claims) {
		t.Fatalf("enrollment did not survive restart: %v", err)
	}
	if _, err := after.Consume(identity, "file:test"); err == nil {
		t.Fatal("enrollment token executed an operation")
	}
	grant, _, _, err := before.MintWithDetails(agent, "binary", []string{"cli:exec"}, "session", "cli:exec", "file:test", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := after.Verify(grant); err == nil {
		t.Fatal("old execution authority survived loss of usage state")
	}
	agent.RecoveryOnly = true
	if _, _, _, err := after.MintWithDetails(agent, "binary", []string{"cli:exec"}, "session", "cli:exec", "file:test", nil, ""); err == nil {
		t.Fatal("reporting recovery minted authority")
	}
}
