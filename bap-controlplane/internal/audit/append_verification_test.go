package audit

import "testing"

func TestAppendVerificationAndIndependentFullVerification(t *testing.T) {
	s := NewStore()
	for _, id := range []string{"one", "two", "three"} {
		_, _ = s.Ingest([]Event{{EventID: id, Decision: "allow"}})
		if valid, err := s.VerifyAppend(); !valid || err != nil {
			t.Fatalf("append verification: %v", err)
		}
		if valid, err := s.VerifyChain(); !valid || err != nil {
			t.Fatalf("full verification: %v", err)
		}
	}
	s.events[0].Decision = "tampered"
	if valid, _ := s.VerifyChain(); valid {
		t.Fatal("full verification missed old-prefix tampering")
	}
	if valid, _ := s.VerifyAppend(); valid {
		t.Fatal("acknowledged after known integrity failure")
	}
}

func TestAppendVerificationRejectsCorruptedNewRecord(t *testing.T) {
	s := NewStore()
	_, _ = s.Ingest([]Event{{EventID: "one", Decision: "allow"}})
	_, _ = s.VerifyAppend()
	_, _ = s.Ingest([]Event{{EventID: "two", Decision: "allow"}})
	s.events[1].Decision = "tampered"
	if valid, _ := s.VerifyAppend(); valid {
		t.Fatal("append verification missed new-record tampering")
	}
}

func TestAuditHashBindsAuthenticatedSessionOwnership(t *testing.T) {
	s := NewStore()
	_, _ = s.Ingest([]Event{{EventID: "owner", SessionID: "session-a", InstanceID: "machine-a", Decision: "allow"}})
	s.events[0].InstanceID = "machine-b"
	if valid, _ := s.VerifyChain(); valid {
		t.Fatal("ownership substitution did not invalidate audit hash")
	}
}
