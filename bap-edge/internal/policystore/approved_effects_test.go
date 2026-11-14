package policystore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Golden vector shared with bap-controlplane/internal/policy: with approvals the payload gains one
// sorted line; without them it is byte-identical to the previous format.
func TestCanonicalPayloadWithApprovedEffects(t *testing.T) {
	base := "bap-policy-v2\nasset=a\nversion=3\ndigest=d\nkill=false\nstrict=false\ntier=t\nzsp_read_exempt=true\nupdated_at=u\n"
	if got := string(canonicalPayload("a", 3, "d", false, false, "t", true, "u")); got != base {
		t.Fatalf("no approvals must not change the payload: %q", got)
	}
	got := string(canonicalPayload("a", 3, "d", false, false, "t", true, "u", "dev:go:test", "dev:go:build", "dev:go:test"))
	if want := base + "approved_effects=dev:go:build,dev:go:test\n"; got != want {
		t.Fatalf("approved effects must be sorted, de-duplicated and signed:\n%q\n%q", got, want)
	}
}

func TestApprovedEffectsAreStoredAndVerified(t *testing.T) {
	cp := newFakeCP(t)
	cp.approved = []string{"dev:go:test", "dev:go:build"}
	s := newManagedStore(t, cp, "asset-A")
	_, _, st, err := s.Current()
	if err != nil {
		t.Fatalf("signed state with approvals must verify: %v", err)
	}
	if len(st.ApprovedEffects) != 2 {
		t.Fatalf("approved effects must be kept from the signed bundle: %v", st.ApprovedEffects)
	}

	// An administrator approval arrives with the next sync.
	cp.approved = append(cp.approved, "fs:file:write")
	cp.version++
	if _, _, err := s.SyncWithServer(cp.srv.URL, "", 2e9); err != nil {
		t.Fatal(err)
	}
	if _, _, st, err = s.Current(); err != nil || len(st.ApprovedEffects) != 3 {
		t.Fatalf("new approval must flow in on sync: %v %v", st.ApprovedEffects, err)
	}
}

func TestStrippingOrForgingApprovalsLocallyFailsClosed(t *testing.T) {
	cp := newFakeCP(t)
	cp.approved = []string{"dev:go:test"}
	s := newManagedStore(t, cp, "asset-A")
	st, _ := s.LoadState()

	for name, edit := range map[string][]string{"stripped": nil, "extra": {"dev:go:test", "fs:file:write"}} {
		forged := st
		forged.ApprovedEffects = edit
		data, _ := json.Marshal(forged)
		if err := os.WriteFile(filepath.Join(s.Directory(), "policy-signed.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := s.Current(); !errors.Is(err, ErrPolicyTampered) {
			t.Errorf("%s approvals must be reported as tampering, got %v", name, err)
		}
	}
}
