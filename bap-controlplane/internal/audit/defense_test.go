package audit

import (
	"bap-controlplane/pkg/types"
	"testing"
)

func TestDefenseEvidenceIsHashBoundAndSnapshotsAreIndependent(t *testing.T) {
	s := NewStore()
	in := Event{EventID: "defense-1", SessionID: "s", Timestamp: "2026-11-19T00:00:00Z", DefenseObservations: []types.DefenseObservation{{EventID: "o1", ActionID: "a1", Layer: 3, Producer: "pinning", Decision: "passed"}}}
	accepted, err := s.IngestAccepted([]Event{in})
	if err != nil || len(accepted) != 1 || accepted[0].HashVersion != 5 {
		t.Fatalf("ingest: %+v %v", accepted, err)
	}
	in.DefenseObservations[0].Decision = "changed input"
	accepted[0].DefenseObservations[0].Decision = "changed accepted"
	s.List(1)[0].DefenseObservations[0].Decision = "changed list"
	s.ListBySession("s")[0].DefenseObservations[0].Decision = "changed session list"
	if valid, err := s.VerifyChain(); !valid || err != nil {
		t.Fatalf("snapshot mutation changed ledger: %v", err)
	}
	s.events[0].DefenseObservations[0].Decision = "tampered"
	if valid, _ := s.VerifyChain(); valid {
		t.Fatal("defense evidence was not bound to the audit hash")
	}
}
