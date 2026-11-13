package learn

import (
	"fmt"
	"path/filepath"
	"testing"

	"bap-edge/internal/capability"
)

func TestProfileGeneratorUsesObservedExactEffectsAndDoesNotApply(t *testing.T) {
	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "toolchain")
	cur := capability.New(ws)
	var events []Event
	for i := 0; i < 3; i++ {
		session := fmt.Sprint(i)
		events = append(events, Event{Project: ws, Session: session, Kind: "fs", Mode: "read", Target: outside, Verdict: "allow", Observed: true, Source: "sandbox"}, Event{Project: ws, Session: session, Kind: "egress", Target: "registry.example:443", Verdict: "allow", Observed: true, Source: "egress-proxy"})
	}
	for _, target := range []string{filepath.Join(ws, ".env"), filepath.Join(filepath.VolumeName(ws)+string(filepath.Separator), ".ssh", "key")} {
		events = append(events, Event{Project: ws, Session: "1", Kind: "fs", Mode: "read", Target: target, Verdict: "allow", Observed: true, Source: "sandbox"})
	}
	events = append(events, Event{Project: ws, Session: "1", Kind: "egress", Target: "169.254.169.254:80", Verdict: "allow", Observed: true, Source: "egress-proxy"})
	got, err := GenerateProfile(events, cur, 3)
	if err != nil || len(got.AddReadOnly) != 1 || got.AddReadOnly[0] != outside || len(got.AddEgress) != 1 || got.AddEgress[0] != "registry.example:443" || !got.RequiresHumanApproval {
		t.Fatalf("recommendation: %+v %v", got, err)
	}
	if len(cur.ReadOnly) != 0 || len(cur.EgressAllow) != 0 || len(got.Profile.ExtraWrite) != 0 {
		t.Fatal("generator mutated the current profile or granted writes")
	}
	if capability.MatchEgress(got.Profile.EgressAllow, "other.example", "443") {
		t.Fatal("host generalized")
	}
	for i := range events {
		events[i].Observed = false
	}
	if _, err := GenerateProfile(events, cur, 3); err == nil {
		t.Fatal("predictions were treated as observed effects")
	}
}
