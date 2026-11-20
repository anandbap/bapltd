package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"bap-edge/internal/authz"
)

// The suite itself runs under an agent, so by default the lineage probe reports "no agent ancestor".
// Tests that exercise the lineage gate install their own probe.
func init() {
	agentLineageProbe = func() (string, bool) { return "", false }
}

func withLineage(t *testing.T, sid string, found bool) {
	t.Helper()
	prev := agentLineageProbe
	agentLineageProbe = func() (string, bool) { return sid, found }
	t.Cleanup(func() { agentLineageProbe = prev })
}

func TestRefuseAgentContext(t *testing.T) {
	t.Run("developer terminal is never refused", func(t *testing.T) {
		t.Setenv("BAP_IN_BROKER", "")
		withLineage(t, "", false)
		if err := refuseAgentContext("x"); err != nil {
			t.Fatalf("no broker marker and no agent ancestor must be allowed, got %v", err)
		}
	})
	t.Run("broker marker is refused", func(t *testing.T) {
		t.Setenv("BAP_IN_BROKER", "1")
		withLineage(t, "", false)
		if err := refuseAgentContext("x"); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
			t.Fatalf("expected human-approval-required refusal, got %v", err)
		}
	})
	t.Run("agent lineage is refused even without the marker", func(t *testing.T) {
		t.Setenv("BAP_IN_BROKER", "")
		withLineage(t, "sess-agent", true)
		err := refuseAgentContext("approving is a human-operator action")
		if !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
			t.Fatalf("a marker-less child of an agent session must be refused, got %v", err)
		}
	})
}

// Every human-only entry point must honour the lineage gate, not just the BAP_IN_BROKER marker.
func TestHumanOnlyEntryPointsRefuseAgentLineage(t *testing.T) {
	e2eEnv(t)
	withLineage(t, "sess-agent", true)

	if err := RunZSP([]string{"approve", "req-deadbeef"}); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
		t.Errorf("zsp approve from an agent descendant must be refused, got %v", err)
	}
	if err := RunZSP([]string{"deny", "req-deadbeef"}); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
		t.Errorf("zsp deny from an agent descendant must be refused, got %v", err)
	}
	if err := RunZSP([]string{"autoapprove", "on"}); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
		t.Errorf("zsp autoapprove on from an agent descendant must be refused, got %v", err)
	}
	if err := RunZSP([]string{"inbox"}); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
		t.Errorf("zsp inbox from an agent descendant must be refused, got %v", err)
	}
	if on, _, _ := authz.AutoApproveStatus(authz.ResolveZSPDir()); on {
		t.Fatal("auto-approve must remain OFF after a refused attempt")
	}
	if humanApprovalChallenge("s", []string{"a"}, []string{"r"}, "g") {
		t.Error("the one-time challenge must not be answerable from an agent descendant")
	}
}

// Usability guard: the read-only and request-side commands an agent legitimately uses keep working
// from inside an agent lineage.
func TestAgentLineageStillAllowsRequestAndInspection(t *testing.T) {
	e2eEnv(t)
	withLineage(t, "sess-agent", true)
	sess := "sess-lineage-usable"

	if err := authorize(sess, "--actions", "fs:file:write", "--resources", "workspace://current", "--max-uses", "5"); err != nil {
		t.Fatalf("requesting a routine grant must still work from an agent, got %v", err)
	}
	if err := RunZSP([]string{"status", "--session-id", sess}); err != nil {
		t.Fatalf("zsp status must still work from an agent, got %v", err)
	}
	if err := RunZSP([]string{"approvals"}); err != nil {
		t.Fatalf("listing approvals must still work from an agent, got %v", err)
	}
	if err := RunZSP([]string{"autoapprove", "status"}); err != nil {
		t.Fatalf("autoapprove status must still work, got %v", err)
	}
	if err := RunZSP([]string{"autoapprove", "off"}); err != nil {
		t.Fatalf("autoapprove off is harmless and must still work, got %v", err)
	}
}

// liveAgentMarker uses positive evidence only: a stale marker (PID reuse), a marker with no birth stamp
// or a marker for another pid must never classify a developer's terminal as an agent.
func TestLiveAgentMarkerRequiresMatchingLiveBirth(t *testing.T) {
	pid := os.Getpid()
	birth := processBirth(pid)
	if birth == "" {
		t.Skip("process birth is unavailable on this platform")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	markerDir := filepath.Join(".bap", "sessions")
	if err := os.MkdirAll(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(m agentSessionMarker) {
		t.Helper()
		raw, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(markerDir, fmt.Sprintf("pid-%d.json", pid)), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(agentSessionMarker{SessionID: "s-live", PID: pid, Birth: birth})
	if sid, ok := liveAgentMarker(pid); !ok || sid != "s-live" {
		t.Fatalf("a marker whose birth matches the live process must be recognised, got %q %v", sid, ok)
	}
	write(agentSessionMarker{SessionID: "s-stale", PID: pid, Birth: birth + "-old"})
	if _, ok := liveAgentMarker(pid); ok {
		t.Error("a marker with a different birth (PID reuse) must be ignored")
	}
	write(agentSessionMarker{SessionID: "s-nobirth", PID: pid})
	if _, ok := liveAgentMarker(pid); ok {
		t.Error("a marker with no birth stamp must be ignored (fail open)")
	}
	write(agentSessionMarker{SessionID: "s-other", PID: pid + 1, Birth: birth})
	if _, ok := liveAgentMarker(pid); ok {
		t.Error("a marker recording another pid must be ignored")
	}
}
